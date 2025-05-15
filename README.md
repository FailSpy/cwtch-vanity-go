# cwtch-vanity-go

A simple Go script that brute-force generates vanity address profiles directly to Cwtch profiles

Remember that generating vanity addresses can take a while depending on the prefix length and your computer's power.  
Every additional character makes it exponentially more expensive.

## Security note

Using a vanity address is fun, but **if you're attempting to be secure, I would advise _not_ using one.**

Why? Because using one may make it easier for people to trick others into thinking they're you. If you can create it, someone with more $$$ than you can create it in a fraction of the time.

See the disadvantages listed here on Onion services' vanity addresses (which is the same addressing scheme that Cwtch uses)
https://community.torproject.org/onion-services/advanced/vanity-addresses/

If you're going to use a vanity address, you should advise your users to also look at the last few characters in the address as well. (the last char will always be `d` though, as this represents the tor onion address version '3')

Every character you encourage contacts to look for is exponentially more compute and time on your adversary's part.

## Getting Started

### Building

Clone this repository and build it:

```bash
go build -o cwtch-vanity main.go
```

This will create a mostly-portable executable file named `cwtch-vanity` (or `cwtch-vanity.exe` on Windows).

### Running

After building, you can run the script from your terminal:

```bash
./cwtch-vanity -prefix <YOUR_PREFIX> [options]
```

Replace `<YOUR_PREFIX>` with the desired letters you want your onion address to start with. **These must be valid Base32 characters (A-Z and 2-7).**

**Example:**

```bash
./cwtch-vanity -prefix hunter2
```

This will start the script searching for an onion address starting with "hunter2".

## Options

*   `-prefix <YOUR_PREFIX>`: **Required**. The desired vanity prefix.
*   `-keep-going`: If provided, the script will keep searching for more vanity addresses with the same prefix after finding the first one. Each found address will generate a new export file.
*   `-password <YOUR_PASSWORD>`: Sets a password for the generated Cwtch profile. If not provided, it defaults to the Cwtch "no password" password ("be gay do crime"). You can alternatively set the `PROFILE_PASSWORD` environment variable.
*   `-cpus <NUM_CPUS>`:  Specify the number of CPU cores to use for searching. Defaults to the number of logical CPU cores available on your system.

## Importing a Generated Profile into Cwtch

Once the script finds a vanity address, it creates a `.tar.gz` file named as the full-length address, which you can import directly into Cwtch.

1.  Open Cwtch.
2.  Hit the '+' button where you would normally add a profile, and choose Import.
3.  Select the `.tar.gz` file the script generated for the address you like.
4.  You will be prompted for a password. If you didn't set one, just hit 'Import profile'. 

Voila! You should now have a new Cwtch profile with your vanity onion address.

## Why wouldn't you use `mkp224o`?
[`mkp224o`](https://github.com/cathugger/mkp224o) is great and would be far preferable, but it takes a shortcut which makes it incompatible with Golang's ed25519 libraries, and thusly, cwtch's way of storing private keys.

To explain further, `mkp224o` creates a Private Key from a seed ("expanding" the key), and after expanding, it will manipulate the Private Key until the matching Public Key results in a desired vanity address.
That is way more efficient as it skips multiple expensive steps, and is compatible with Tor's implementation because Tor uses the "expanded" form of the private key, meaning it doesn't care about the seed. 

But cwtch adopts Golang crypto's format of ed25519 keys. It stores the _pre-expanded_ seed to represent the private key, and the public key. 
This fundamental difference means it's not possible to use `mkp224o`'s speedup technique and the keys it generates.

Rather than reimplementing the entire crypto stack in Go to support working with post-expanded forms of keys and the risks that would come with that, 
I made this little package which works with Cwtch libraries to brute-force _seeds_ for ed25519 keys and directly exports them as Cwtch profiles.

You could probably modify `mkp224o` to generate directly with seeds, which done right would likely be more performant than this, but since I was only doing this for Cwtch, 
I preferred this all-in-one solution that goes straight from keygen to Cwtch profile.
