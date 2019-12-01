package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"github.com/jasonlvhit/gocron"
	"github.com/jessevdk/go-flags"
	"github.com/likexian/doh-go"
	"github.com/likexian/doh-go/dns"
	"io"
	"log"
	"net"
	"os"
	"reflect"
	"strconv"
	"strings"
	"time"
)

type Opts struct {
	// Example of verbosity with level
	Action string `short:"a" long:"action" choice:"encrypt" choice:"decrypt" choice:"knock" choice:"dns" default:"knock" description:"Run procedure" required:"true"`
	//Gui bool `short:"g" long:"gui"  description:"Show window for user enter pin code"`
	Password string `short:"p" long:"password" description:"Password required if used encryption algorithm"`
	Pin      string `long:"pin" description:"This salt for password"`
	Loop     uint64 `short:"l" long:"loop" description:"Schedule every minutes" default:"0"`
	Command  string `short:"c" long:"command" description:"Command for run knock string or encrypted string in coding base64" required:"true"`
	Verbose  bool   `short:"v" long:"verbose" description:"Show verbose debug information"`
	Author   bool   `long:"author" description:"Vasilev Kirill\nhttps://mikrotik.me"`
}

var options Opts

var parser = flags.NewParser(&options, flags.Default)

func main() {

	if _, err := parser.Parse(); err != nil {
		if flagsErr, ok := err.(*flags.Error); ok && flagsErr.Type == flags.ErrHelp {

			os.Exit(0)
		} else {

			os.Exit(1)
		}
	}
	if options.Action == "encrypt" {
		ActionEncypt()
		return
	}
	if options.Action == "decrypt" {
		ActionDecrypt()
		return
	}
	if options.Action == "knock" {
		if options.Loop > 0 {
			ActionKnock()
			s := gocron.NewScheduler()
			s.Every(options.Loop).Minute().Do(ActionKnock)
			<-s.Start()
		} else {
			ActionKnock()
			return
		}

	}
	if options.Action == "dns" {
		if options.Loop > 0 {
			ActionDns()
			s := gocron.NewScheduler()
			s.Every(options.Loop).Minute().Do(ActionDns)
			<-s.Start()

		} else {
			ActionDns()
			return
		}
	}

}

func ActionKnock() {

	Verb("Start Knock Procedure")
	if len(options.Password) > 0 {
		Verb("--password isset")
	}
	if len(options.Pin) > 0 {
		Verb("--pin isset")
	}
	if len(options.Command) < 1 {
		Verb("Required --command argument")
		log.Fatal("Need --command")
	}
	if len(options.Password) > 0 {
		Verb("Create Hash")
		hash := createHash(options.Password, options.Pin)
		Verb("hash:" + hash)
		Verb("Starting decryption --command")
		dynstring, err := decrypt(options.Command, hash)
		if err != nil {
			Verb("Result:Error")
			Verb("Error Message:" + err.Error())
			log.Fatal("Bad Decryption process change password or pin")
		}
		options.Command = dynstring
	}
	Verb("--command for job: " + options.Command)
	if len(options.Command) < 5 {
		Verb("--command need minimal 5 charset")
		log.Fatal("Bad --command string")
	}
	if err := RunCommand(options.Command); err != nil {
		Verb("Bad knock")
		Verb(err.Error())
	}

}
func ActionDns() {

	Verb("Start DNS procedure")
	Verb("Get TXT record from domain " + options.Command)
	response, err := getDNSDOH(options.Command, dns.TypeTXT)
	if err != nil {
		Verb("DNS Error")
		log.Fatal(err.Error())
	}
	if len(response) == 0 {
		Verb("No TXT records")
		log.Fatal("Bad")
	}
	if len(options.Password) > 0 {

	}
	Verb("TXT record for domain count=" + strconv.Itoa(len(response)))

	Verb("Running loop")
	for i, s := range response {
		Verb("Index:" + strconv.Itoa(i) + " :" + s)

		if s[0:2] == "H:" {
			Verb("Command not encrypted")
			if err := RunCommand(s); err != nil {
				Verb("Bad knock")
				Verb(err.Error())
			}
			continue
		}

		if len(options.Password) > 0 {
			pass := createHash(options.Password, options.Pin)
			Verb("Decrypt string")
			Verb("Use hash:" + pass)
			commandst, err := decrypt(s, pass)
			if err != nil {
				Verb("Error Decrypt")
				Verb(err.Error())
				continue
			}

			if err := RunCommand(commandst); err != nil {
				Verb("Bad knock")
				Verb(err.Error())
			}
			continue
		}

	}
}

func RunCommand(s string) (err error) {
	Verb("Parse string:" + s)
	parsemap, err := ParseCommand(s)
	if err != nil {
		Verb("Parse Fail")
		return errors.New("Parse Error")
	}
	Verb("Parse OK")
	Verb("Running knock for command:" + s)
	if _, err := RunVasya(parsemap); err != nil {
		Verb("Error knock")
		Verb(err.Error())
	}
	Verb("knock Cancel")
	return nil
}

func ActionDecrypt() {
	Verb("Start Decrypt Procedure")
	if len(options.Password) < 1 {
		Verb("Required --password argument")
		log.Fatal("Need --password")
	}
	if len(options.Command) < 1 {
		Verb("Required --Command argument for decrypt")
		log.Fatal("Need --command")
	}

	if len(options.Pin) < 1 {
		Verb("argument --pin empty")
	}
	Verb("Create Hash")
	hash := createHash(options.Password, options.Pin)
	Verb("hash:" + hash)
	Verb("Starting decryption")
	dynstring, err := decrypt(options.Command, hash)
	if err != nil {
		Verb("Result:Error")
		Verb("Error Message:" + err.Error())
		log.Fatal("Bad Decryption process change password or pin")
	}
	Verb("Result:OK")
	Verb("Result string:" + dynstring)
	log.Printf("Result: " + dynstring)
	os.Exit(0)

}

func ActionEncypt() {
	Verb("Start Encrypt Procedure")
	if len(options.Password) < 1 {
		Verb("Required password argument")
		log.Fatal("Need password")
	}
	if len(options.Command) < 1 {
		Verb("Required Command argument for encrypt")
		log.Fatal("Need Command")
	}
	Verb("Test argument --command string")
	if _, err := ParseCommand(options.Command); err != nil {
		Verb("Result:Error")
		Verb("Error Message:" + err.Error())
		Verb(options.Command)
		log.Fatal("argument --command is not valid")
	}
	Verb("Result:OK")
	if len(options.Pin) < 1 {
		Verb("argument --pin empty")
	}
	Verb("Create Hash")
	hash := createHash(options.Password, options.Pin)
	Verb("hash:" + hash)
	Verb("Starting encryption")
	encstring, err := encrypt([]byte(options.Command), hash)
	if err != nil {
		Verb("Result:Error")
		Verb("Error Message:" + err.Error())
		log.Fatal("Bad Encryption proccess")
	}
	Verb("Result:OK")
	Verb("Result string:" + encstring)
	log.Printf("Result: " + encstring)
	os.Exit(0)

}

func Verb(str string) {
	if options.Verbose {
		log.Printf(str)
	}
}

func parseDelim(s string) (strm map[string]string, err error) {
	params := strings.Split(s, ":")
	if len(params) != 2 {
		return nil, errors.New("Bad parse need delimeter :")
	}
	m := make(map[string]string)
	if params[0] == "T" || params[0] == "U" {
		port, err := strconv.Atoi(params[1])
		if err != nil {
			return nil, errors.New("Port not is numeric")
		}
		if port < 1 || port > 65535 {
			return nil, errors.New("Port not in range 1-65535")
		}

		switch params[0] {
		case "T":
			m["tcp"] = params[1]
		case "U":
			m["udp"] = params[1]
		}
		return m, nil
	}
	if params[0] == "H" {
		m["host"] = params[1]
		return m, nil
	}
	return nil, errors.New("Bad Parse")
}

func ParseCommand(s string) (paramslist map[int]map[string]string, err error) {
	params := strings.Split(s, ",")
	if len(params) < 2 {
		return nil, errors.New("Small Count Before Split string")
	}
	i := 1
	m := make(map[int]map[string]string)
	for _, v := range params {
		g, err := parseDelim(v)
		if err != nil {
			return nil, errors.New(err.Error())
		}
		m[i] = g
		i++
	}
	return m, nil

}

func VasyaConnect(m map[string]string, ipaddress string) bool {
	if m == nil {
		return false
	}
	keys := reflect.ValueOf(m).MapKeys()
	protocol := keys[0].String()
	port := m[protocol]
	service := ipaddress + ":" + port
	Verb("Knock  " + service + " protocol " + protocol)
	conn, _ := net.DialTimeout(protocol, service, 100000000)
	if protocol == "udp" {
		_, _ = conn.Write([]byte("a"))
	}
	Verb("Knock End")
	return false
}

func RunVasya(strm map[int]map[string]string) (nil, err error) {
	if len(strm[1]["host"]) == 0 {
		return nil, errors.New("Bad Host")
	}
	var h []string
	host := strm[1]["host"]

	ip := net.ParseIP(host)
	if len(ip) != 0 {
		h = append(h, host)
	} else {
		dnsres, err := getDNSDOH(host, dns.TypeA)
		//dnsres, err := net.LookupIP(host)
		if err != nil {
			return nil, errors.New("Bad query DNS Lookup")
		}
		for _, ip := range dnsres {
			adr := ip
			h = append(h, adr)
		}
	}
	if len(h) < 1 {
		return nil, errors.New("no resolve addreses")
	}

	for _, ipaddress := range h {
		i := 2
		for range strm {
			Verb("Run To host " + ipaddress)
			VasyaConnect(strm[i], ipaddress)
			i++
		}
	}

	return nil, nil
}

func createHash(key string, pin string) (stringValue string) {
	Verb("Key:" + key)
	if len(pin) > 0 {
		Verb("pin:" + pin)
		key = pin + key + pin
	}
	hasher := md5.New()
	hasher.Write([]byte(key))
	return hex.EncodeToString(hasher.Sum(nil))
}

func encrypt(data []byte, passphrase string) (stringValue string, err error) {
	block, _ := aes.NewCipher([]byte(passphrase))

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", errors.New(err.Error())
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return "", errors.New(err.Error())
	}
	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	res := base64.StdEncoding.EncodeToString(ciphertext)
	return res, nil
}

func decrypt(s string, passphrase string) (stringValue string, err error) {
	ciphertext, _ := base64.StdEncoding.DecodeString(s)
	c, err := aes.NewCipher([]byte(passphrase))
	//c, err := aes.NewCipher([]byte(key))
	if err != nil {
		return "", errors.New(err.Error())
	}
	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return "", errors.New(err.Error())
	}
	nonceSize := 12
	if len(ciphertext) < nonceSize {
		return "", errors.New("Size nonece Bad")
	}
	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]

	result, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", errors.New(err.Error())
	}
	return string(result), nil
}

func getDNSDOH(record string, t dns.Type) (str []string, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c := doh.Use(doh.CloudflareProvider, doh.GoogleProvider)
	rec := dns.Domain(record)
	rsp, err := c.Query(ctx, rec, t)
	if err != nil {
		return nil, errors.New("Error use DoH")
	}
	c.Close()
	var ret []string
	for _, a := range rsp.Answer {
		ret = append(ret, a.Data[1:len(a.Data)-1])
	}
	return ret, nil
}
