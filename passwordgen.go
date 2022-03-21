package main

import (
	"flag"
	"fmt"
	"log"
	"math/rand"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/dlclark/regexp2"
)

var pwdLength int

var mCharacters int
var mNumbers int
var mSpCharacters int

var sC int
var lC int
var n int
var spC int

var help bool
var cWithout bool
var lessSecure bool = false

var checkPassword string

var sCharacters string = "abcdefghijklmnopqrstuvwxyz"
var lCharacters string = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
var numbers string = "0123456789"
var spCharacters string = "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~"

func init() {
	flag.IntVar(&pwdLength, "l", 8, "Set the amount of characters for the password")
	flag.IntVar(&mCharacters, "char", 0, "Minimum set of letters in your password")
	flag.IntVar(&mNumbers, "num", 0, "Minimum set of numbers in your password")
	flag.IntVar(&mSpCharacters, "spChar", 0, "Minimum set of special characters for in your password")
	flag.BoolVar(&cWithout, "Y", false, "Continue without error.")
	flag.BoolVar(&help, "h", false, "HELP")
	flag.StringVar(&checkPassword, "check", "", "Check your own password for the security standard")

	flag.Parse()

	if help {
		fmt.Println("Usage of 'PasswordGen':")
		flag.PrintDefaults()
		fmt.Println("-----------------------")
		fmt.Println("To make your password secure the password need a small and capital letter, a number and a special character. With a length of 8 or more it is hard for hackers to get your password.")
		os.Exit(0)
	}

	if checkPassword == "" {
		if mCharacters + mNumbers + mSpCharacters > pwdLength {
			fmt.Println("Your minimum requirements are:", mCharacters + mNumbers + mSpCharacters, "characters.\nBut your password length is only", pwdLength, "characters long.\nMake your password longer via the -l flag or change your requirements.")
			os.Exit(0)
		}
	
		if pwdLength < 8 {
			fmt.Println("A password with the lenght of", pwdLength, "is not secure. Please use a length of 8 or more.")
			os.Exit(111)
		}
	}
}

func main() {
	if checkPassword != "" {
		check, _ := funcCheckPassword(checkPassword)

		if check {
			fmt.Println("Your password is secure")
		} else {
			fmt.Println("Your password is insecure")
		}
		os.Exit(0)
	}

	c,e := createPassword()

	if e != nil {
		log.Fatal(e.Error())
	} else {
		if lessSecure {
			fmt.Println("Your password is less secure.")
		}
		writeToFile(c)
		fmt.Println("Your new password is:", c)
	}
}

func createPassword() (string, error){
	rand.Seed(time.Now().UnixNano())

	var F_sCharacters string
	var F_lCharacters string
	var F_numbers string
	var F_spCharacters string

	var e error

	totalMin := mCharacters + mNumbers + mSpCharacters
	pwdGenLength := (pwdLength - 4) - totalMin

	if(mCharacters > 0 || mNumbers > 0 || mSpCharacters > 0) {

		for i := 0; i < pwdGenLength - 4; i++ {
			y := rand.Intn(4)

			switch y {
			case 0:
				mCharacters++
			case 1:
				mCharacters++
			case 2:
				mNumbers++
			case 3:
				mSpCharacters++
			}
		}

		if mCharacters > 2 {
			sC++
			lC++

			for i := 0; i < mCharacters - 2; i++ {
				y := rand.Intn(2)
	
				switch y {
				case 0:
					sC++
				case 1:
					lC++
				}
			}
		} else {
			for i := 0; i < mCharacters; i++ {
				y := rand.Intn(2)
	
				switch y {
				case 0:
					sC++
				case 1:
					lC++
				}
			}
		}

		n = mNumbers
		spC = mSpCharacters

		sC, e = countInt(sC)
		if e != nil {
			return "", fmt.Errorf(e.Error())
		}

		lC, e = countInt(lC)
		if e != nil {
			return "", fmt.Errorf(e.Error())
		}

		n, e = countInt(n)
		if e != nil {
			return "", fmt.Errorf(e.Error())
		}

		spC, e = countInt(spC)
		if e != nil {
			return "", fmt.Errorf(e.Error())
		}

		for i := sC + lC + n + spC; i < pwdLength; i++ {
			y := rand.Intn(4)

			switch y {
			case 0:
				sC++
			case 1:
				lC++
			case 2:
				n++
			case 3:
				spC++
			}
		}

		F_sCharacters, e = randomCharacters(0, sC)
		F_lCharacters, e = randomCharacters(1, lC)
		F_numbers, e = randomCharacters(2, n)
		F_spCharacters, e = randomCharacters(3, spC)
	} else {
		for i := 0; i < pwdGenLength; i++ {
			y := rand.Intn(4)

			switch y {
			case 0:
				sC++
			case 1:
				lC++
			case 2:
				n++
			case 3:
				spC++
			}
		}

		F_sCharacters, e = randomCharacters(0, sC + 1)
		F_lCharacters, e = randomCharacters(1, lC + 1)
		F_numbers, e = randomCharacters(2, n + 1)
		F_spCharacters, e = randomCharacters(3, spC + 1)
	}

	password := F_sCharacters + F_lCharacters + F_numbers + F_spCharacters
	var passwordCharacters []string

    for _,c := range strings.Split(password, "") {
		passwordCharacters = append(passwordCharacters, c)
	}
    rand.Shuffle(len(passwordCharacters), func(i, j int) {
        passwordCharacters[i], passwordCharacters[j] = passwordCharacters[j], passwordCharacters[i]
    })

	password = ""

	for _,c := range passwordCharacters {
		password += c
	}

	if e != nil {
		return "", fmt.Errorf(e.Error())
	} else {
		return password, nil
	}
}

func countInt(interger int) (int, error) {
	if interger == 0 {
		if sC + lC + n + spC >= pwdLength {
			if !cWithout {
				return interger, fmt.Errorf("Your new password doesn't meet the security standards. Please check the help for the security stadards.")
			} else {
				lessSecure = true
				return interger, nil
			}
		} else {
			interger++
			return interger, nil
		}
	} else {
		return interger, nil
	}
}

func randomCharacters(char int, amount int) (string, error) {
	var characters string

	switch char {
	case 0:
		for i := 0; i < amount; i++ {
			c,e := getCharacter(sCharacters)
			if e != nil {
				return "", fmt.Errorf(e.Error())
			} else {
				characters += c
			}
		}
	case 1:
		for i := 0; i < amount; i++ {
			c,e := getCharacter(lCharacters)
			if e != nil {
				return "", fmt.Errorf(e.Error())
			} else {
				characters += c
			}
		}
	case 2:
		for i := 0; i < amount; i++ {
			c,e := getCharacter(numbers)
			if e != nil {
				return "", fmt.Errorf(e.Error())
			} else {
				characters += c
			}
		}
	case 3:
		for i := 0; i < amount; i++ {
			c,e := getCharacter(spCharacters)
			if e != nil {
				return "", fmt.Errorf(e.Error())
			} else {
				characters += c
			}
		}
	}

	return characters, nil
}

func writeToFile(password string) {
	timeNow := strconv.Itoa(time.Now().Day()) + "-" + strconv.Itoa(int(time.Now().Month())) + "-" + strconv.Itoa(time.Now().Year()) 
	f, e := os.OpenFile("password - " + timeNow + ".txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)

	if e != nil {
		log.Println("Your password is:", password)
        log.Fatal(e)
    }

	var hour string
	var minutes string
	var second string

	if len(strconv.Itoa(time.Now().Hour())) == 1 {
		hour = "0" + strconv.Itoa(time.Now().Hour())
	} else {
		hour = strconv.Itoa(time.Now().Hour())
	}

	if len(strconv.Itoa(time.Now().Minute())) == 1 {
		minutes = "0" + strconv.Itoa(time.Now().Minute())
	} else {
		minutes = strconv.Itoa(time.Now().Minute())
	}

	if len(strconv.Itoa(time.Now().Second())) == 1 {
		second = "0" + strconv.Itoa(time.Now().Second())
	} else {
		second = strconv.Itoa(time.Now().Second())
	}

	// remember to close the file
    defer f.Close()

	if lessSecure {
		_, err := f.WriteString(hour + ":" + minutes + ":" + second + ": " + password + " | less secure\n")

		if err != nil {
			log.Fatal(err)
		}
	} else {
		_, err := f.WriteString(hour + ":" + minutes + ":" + second + ": " + password + "\n")

		if err != nil {
			log.Fatal(err)
		}
	}
}

func getCharacter(char string) (string, error) {
	nChar := rand.Intn(len(char))
	var tChar []string

	for _,c := range strings.Split(char, "") {
		tChar = append(tChar, c)
	}

	if len(tChar) == 0 {
		return "", fmt.Errorf("No characters given.")
	} else {
		return tChar[nChar], nil
	}
}

func funcCheckPassword(password string) (bool, error) {
	regex, _ := regexp2.Compile("(?=.*[0-9])(?=.*[a-z])(?=.*[A-Z])(?=.*[!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~]).{8,}", 0)

	matched, _ := regex.MatchString(password)

	return matched, nil
}