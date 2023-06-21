package main

import (
	"encoding/hex"
	"fmt"
	"log"
	"math/big"
	"math/rand"
	"net"
	"os"
)

const (
	HOST = "localhost"
	PORT = "1337"
	TYPE = "tcp"
	FLAG = "KMACTF{flag}"
)

func tamper(conn net.Conn, original []*big.Int) {
	conn.Write([]byte("Original votes (each vote is encoded in 64 hex characters):\n"))
	for _, ori := range original {
		buf := make([]byte, 32)
		ori.FillBytes(buf)
		conn.Write([]byte(hex.EncodeToString(buf)))
	}

	conn.Write([]byte("\nTampered votes:\n"))
	buf := make([]byte, 64*len(original))
	_, err := conn.Read(buf)
	if err != nil {
		conn.Close()
		return
	}

	for idx, tamper := range original {
		_, ok := tamper.SetString(string(buf[idx*64:idx*64+64]), 16)
		if !ok {
			conn.Close()
			return
		}
	}
}

func main() {
	listen, err := net.Listen(TYPE, HOST+":"+PORT)
	if err != nil {
		log.Fatal(err)
		os.Exit(1)
	}
	// close listener
	defer listen.Close()
	for {
		conn, err := listen.Accept()
		if err != nil {
			log.Fatal(err)
			os.Exit(1)
		}
		go handleRequest(conn)
	}
}

func handleRequest(conn net.Conn) {
	n := 10 // number of voters
	k := 5  // number of authorities
	t := 2  // `threshold` the scheme requires t + 1 honest authorities to derive the final result

	conn.Write([]byte("[+] Public ID of available authorities:\n"))
	authorities := make([]*authority, k)
	for i := 0; i < k; i++ {
		authorities[i] = init_authority()
		conn.Write([]byte(fmt.Sprintf("%d\n", authorities[i].id)))
	}

	voters := make([]*voter, n)
	for i := 0; i < n; i++ {
		voters[i] = init_voter(t, rand.Intn(2) == 1) //polynomial have degree 2
		voters[i].votes = make([]*big.Int, k)
		for j := 0; j < k; j++ {
			voters[i].votes[j] = voters[i].eval(authorities[j].id) //f(id[0->5])
		}
	}

	conn.Write([]byte("[+] One voter is being hacked.\n"))
	tamper(conn, voters[0].votes)

	// voters send votes to authorities
	for i := 0; i < k; i++ {
		votes := make([]*big.Int, n)
		for j := 0; j < n; j++ {
			votes[j] = voters[j].votes[i]
		}
		authorities[i].votes =  // sum 0f voters's vote: f0(id), f1(id), ..., f9(id)
	}

	rand.Shuffle(len(authorities), func(i, j int) {
		authorities[i], authorities[j] = authorities[j], authorities[i]
	})

	ids := get_ids(authorities[:t+1]) // list of authorities's id
	votes := get_votes(authorities[:t+1]) // list of authorities's votes f0(id), f1(id), ... f9(id)
	result := lagrange_interpolate(ids, votes)

	if result.Cmp(big.NewInt(1337)) == 0 {
		conn.Write([]byte(fmt.Sprintf("[*] There are 1337 votes, seems like someone is hacking! :( The flag is %s\n", FLAG)))
	} else {
		if result.Cmp(big.NewInt(int64(n))) != 1 {
			conn.Write([]byte(fmt.Sprintf("[*] We got %d yes from everyone.\n", result)))	
		} else {
			conn.Write([]byte(fmt.Sprintf("[*] We got %d yes. Suspicious...\n", result)))
		}
	}
	conn.Close()
}
