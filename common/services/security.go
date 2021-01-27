/*
 Copyright 2020, 2021 Jan Dittberner


 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at

     http://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.
*/

package services

import (
	"crypto/rand"

	log "github.com/sirupsen/logrus"
)

func GenerateKey(length int) []byte {
	key := make([]byte, length)
	read, err := rand.Read(key)
	if err != nil {
		log.Fatalf("could not generate key: %s", err)
	}
	if read != length {
		log.Fatalf("read %d bytes, expected %d bytes", read, length)
	}
	return key
}
