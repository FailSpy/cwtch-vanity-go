package main

import (
	"archive/tar"
	"compress/gzip"
	"crypto/ed25519"
	"crypto/rand"
	"flag"
	"fmt"
	"io"
	"strings"
	"os"
	"os/signal"
	"syscall"
	"log"
	"runtime"
	"sync"
	"sync/atomic"
	"time"
	"encoding/base32"

	"git.openprivacy.ca/openprivacy/connectivity/tor"

	"cwtch.im/cwtch/peer"
	"cwtch.im/cwtch/model"
	"cwtch.im/cwtch/model/attr"
	"cwtch.im/cwtch/model/constants"
	_ "github.com/mutecomm/go-sqlcipher/v4"

	"path"
	"path/filepath"

)

const versionFile = "VERSION"
const version = "2"
const saltFile = "SALT"
const dbFile = "db"

// Reimplemented (*peer.CwtchProfileStorage) Export here to have every export have a unique Profile ID
// Otherwise attempting to import multiple profiles from the same run will fail
func Export(cps *peer.CwtchProfileStorage, filename string) error {
	profileDB := filepath.Join(cps.ProfileDirectory, dbFile)
	profileSalt := filepath.Join(cps.ProfileDirectory, saltFile)
	profileVersion := filepath.Join(cps.ProfileDirectory, versionFile)

	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("could not create tarball file '%s', got error '%s'", filename, err.Error())
	}
	defer file.Close()

	gzipWriter := gzip.NewWriter(file)
	defer gzipWriter.Close()

	tarWriter := tar.NewWriter(gzipWriter)
	defer tarWriter.Close()

	// Main line that differs from original impl:
	profilePath := model.GenerateRandomID()

	err = addFileToTarWriter(profilePath, profileDB, tarWriter)
	if err != nil {
		return fmt.Errorf("could not add file '%s', to tarball, got error '%s'", profileDB, err.Error())
	}

	err = addFileToTarWriter(profilePath, profileSalt, tarWriter)
	if err != nil {
	    return fmt.Errorf("could not add file '%s', to tarball, got error '%s'", profileSalt, err.Error())
	}

	err = addFileToTarWriter(profilePath, profileVersion, tarWriter)
	if err != nil {
	    return fmt.Errorf("could not add file '%s', to tarball, got error '%s'", profileVersion, err.Error())
	}

	return nil
}

func addFileToTarWriter(profilePath string, filePath string, tarWriter *tar.Writer) error {
	file, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("could not open file '%s', got error '%s'", filePath, err.Error())
	}
	defer file.Close()

	stat, err := file.Stat()
	if err != nil {
		return fmt.Errorf("could not get stat for file '%s', got error '%s'", filePath, err.Error())
	}

	header := &tar.Header{
		// Note: we are using strings.Join here deliberately so that we can import the profile
		// in a cross platform way (e.g. using filepath here would result in different names on Windows v.s Linux)
		Name:    strings.Join([]string{profilePath, stat.Name()}, "/"),
		Size:    stat.Size(),
		Mode:    int64(stat.Mode()),
		ModTime: stat.ModTime(),
	}

	err = tarWriter.WriteHeader(header)
	if err != nil {
		return fmt.Errorf("could not write header for file '%s', got error '%s'", filePath, err.Error())
	}

	_, err = io.Copy(tarWriter, file)
	if err != nil {
		return fmt.Errorf("could not copy the file '%s' data to the tarball, got error '%s'", filePath, err.Error())
	}

	return nil
}

func initV2Directory(directory, password string) ([32]byte, [128]byte, error) {
	os.MkdirAll(directory, 0700)

	key, salt, err := peer.CreateKeySalt(password)
	if err != nil {
		fmt.Printf("Could not create key for profile store from password: %v\n", err)
		return [32]byte{}, [128]byte{}, err
	}

	if err = os.WriteFile(path.Join(directory, versionFile), []byte(version), 0600); err != nil {
		fmt.Printf("Could not write version file: %v", err)
		return [32]byte{}, [128]byte{}, err
	}

	if err = os.WriteFile(path.Join(directory, saltFile), salt[:], 0600); err != nil {
		fmt.Printf("Could not write salt file: %v", err)
		return [32]byte{}, [128]byte{}, err
	}

	return key, salt, nil
}

func main() {
	vanityPrefix := flag.String("prefix", "", "Desired vanity prefix for onion address")
	keepGoing := flag.Bool("keep-going", false, "Keep searching for vanities with the same prefix after finding one")
	passwordFlag := flag.String("password", "", "Password for the Cwtch profile")
	cpus := flag.Int("cpus", runtime.NumCPU(), "Number of CPUs to use")
	flag.Parse()

	if *vanityPrefix == "" {
		fmt.Println("Please specify a vanity prefix using -prefix flag")
		os.Exit(1)
	}


	validBase32Chars := "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
	upperPrefix := strings.ToUpper(*vanityPrefix)

	for _, c := range upperPrefix {
		if !strings.ContainsRune(validBase32Chars, c) {
			log.Fatalf("Prefix contains invalid character for Base32 charset: '%c'", c)
		}
	}

	password := "be gay do crime" // default "no password" password in cwtch
	if *passwordFlag != "" {
	    password = *passwordFlag
	} else if envPass := os.Getenv("PROFILE_PASSWORD"); envPass != "" {
	    password = envPass
	}

	/// CWTCH SETUP

	profileDir := filepath.Join(os.TempDir(), model.GenerateRandomID())

	err := os.MkdirAll(profileDir, 0700)
	if err != nil {
		log.Fatalf("Failed to create temporary directory: %v", err)
	}
	defer os.RemoveAll(profileDir)

	_, _, errX := initV2Directory(profileDir, password)
	if errX != nil {
		log.Fatalf("Failed to create dummy encryption store: %v", errX)
	}

	cwtchStore, err := peer.CreateEncryptedStore(profileDir, password)
	if err != nil {
		log.Fatalf("Failed to create encrypted store: %v", err)
	}

	peer.NewProfileWithEncryptedStorage(*vanityPrefix, cwtchStore)

	/// CWTCH SETUP DONE

	numCPUs := *cpus
	fmt.Printf("Using %d CPU cores to find vanity address with prefix: %s\n", numCPUs, *vanityPrefix)

	resultChan := make(chan ed25519.PrivateKey)
	stopWorkers := make(chan struct{})

	var attempts uint64 = 0
	stopCounting := make(chan bool)
	go func() {
		startTime := time.Now()
		lastAttempts := uint64(0)
		ticker := time.NewTicker(1 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				currentAttempts := atomic.LoadUint64(&attempts)
				elapsed := time.Since(startTime).Seconds()
				attemptsDelta := currentAttempts - lastAttempts
				fmt.Printf("Attempts: %d, Rate: %.2f/sec, Total rate: %.2f/sec\n",
					currentAttempts,
					float64(attemptsDelta),
					float64(currentAttempts)/elapsed)
				lastAttempts = currentAttempts
			case <-stopCounting:
				return
			}
		}
	}()

	// Set up signal handling
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-signals
		fmt.Println("\nInterrupt received. Shutting down gracefully...")
		close(stopWorkers)
		close(stopCounting)
		time.Sleep(5000 * time.Millisecond)
		os.Exit(1)
	}()

	// Start workers
	var wg sync.WaitGroup
	for i := 0; i < numCPUs; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			findVanityAddress(upperPrefix, resultChan, &attempts, *keepGoing, stopWorkers)
		}()
	}

	for {
		select {
		case privateKey := <-resultChan:
			publicKey := privateKey.Public().(ed25519.PublicKey)

			// Confirmed vanity, so now generate the full onion address from the found key
			onionAddress := tor.GetTorV3Hostname(publicKey)

			fmt.Printf("%s\n",onionAddress)

			onionAttrPath := attr.PublicScope.ConstructScopedZonedPath(attr.ProfileZone.ConstructZonedPath(constants.Onion)).ToString()
			err = cwtchStore.StoreProfileKeyValue(peer.TypeAttribute, onionAttrPath, []byte(onionAddress))
			if err != nil {
				log.Fatalf("Failed to store onion address: %v", err)
			}

			err = cwtchStore.StoreProfileKeyValue(peer.TypePrivateKey, "Ed25519PrivateKey", privateKey)
			if err != nil {
				log.Fatalf("Failed to store private key: %v", err)
			}
			err = cwtchStore.StoreProfileKeyValue(peer.TypePublicKey, "Ed25519PublicKey", publicKey)
			if err != nil {
				log.Fatalf("Failed to store public key: %v", err)
			}

			exportFileName := fmt.Sprintf("%s.tar.gz", onionAddress)

			Export(cwtchStore, exportFileName)

			if !*keepGoing {
				return
			}
		case <-stopWorkers:
			fmt.Println("Main loop received stop signal.")
			return
		}
	}

	wg.Wait()
}

func findVanityAddress(prefix string, resultChan chan<- ed25519.PrivateKey, attempts *uint64, keepGoing bool, stop <-chan struct{}) {
	for {
		select {
		case <-stop:
			return
		default:
			publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				continue
			}

			serviceID := base32.StdEncoding.EncodeToString(publicKey)

			atomic.AddUint64(attempts, 1)

			if serviceID[:len(prefix)] == prefix {
				resultChan <- privateKey

				if !keepGoing {
					return
				}
			}
		}
	}
}
