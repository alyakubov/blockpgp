/*
   Hockeypuck - OpenPGP key server
   Copyright (C) 2012-2014  Casey Marshall

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU Affero General Public License as published by
   the Free Software Foundation, version 3.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU Affero General Public License for more details.

   You should have received a copy of the GNU Affero General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

package pghkp

import (
	"bytes"
	"crypto/md5"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	_ "github.com/lib/pq"
	"gopkg.in/errgo.v1"

	"gopkg.in/hockeypuck/hkp.v1/jsonhkp"
	hkpstorage "gopkg.in/hockeypuck/hkp.v1/storage"
	log "gopkg.in/hockeypuck/logrus.v0"
	"gopkg.in/hockeypuck/openpgp.v1"
)

const (
	maxFingerprintLen = 40
)

type storage struct {
	*sql.DB
	dbName string

	mu        sync.Mutex
	listeners []func(hkpstorage.KeyChange) error
}

var _ hkpstorage.Storage = (*storage)(nil)

var crTablesSQL = []string{
	`CREATE TABLE IF NOT EXISTS keys (
rfingerprint TEXT NOT NULL,
doc jsonb NOT NULL,
ctime TIMESTAMP WITH TIME ZONE NOT NULL,
mtime TIMESTAMP WITH TIME ZONE NOT NULL,
md5 TEXT NOT NULL,
keywords tsvector
)`,
	`CREATE TABLE IF NOT EXISTS subkeys (
rfingerprint TEXT NOT NULL,
rsubfp TEXT NOT NULL
)`,
}

var crIndexesSQL = []string{
	`ALTER TABLE keys ADD CONSTRAINT keys_pk PRIMARY KEY (rfingerprint);`,
	`ALTER TABLE keys ADD CONSTRAINT keys_md5 UNIQUE (md5);`,
	`CREATE INDEX keys_rfp ON keys(rfingerprint text_pattern_ops);`,
	`CREATE INDEX keys_ctime ON keys (ctime);`,
	`CREATE INDEX keys_mtime ON keys (mtime);`,
	`CREATE INDEX keys_keywords ON keys USING gin(keywords);`,

	`ALTER TABLE subkeys ADD CONSTRAINT subkeys_pk PRIMARY KEY (rsubfp);`,
	`ALTER TABLE subkeys ADD CONSTRAINT subkeys_fk FOREIGN KEY (rfingerprint) REFERENCES keys(rfingerprint);`,
	`CREATE INDEX subkeys_rfp ON subkeys(rsubfp text_pattern_ops);`,
}

var drConstraintsSQL = []string{
	`ALTER TABLE keys DROP CONSTRAINT keys_pk;`,
	`ALTER TABLE keys DROP CONSTRAINT keys_md5;`,
	`DROP INDEX keys_rfp;`,
	`DROP INDEX keys_ctime;`,
	`DROP INDEX keys_mtime;`,
	`DROP INDEX keys_keywords;`,

	`ALTER TABLE subkeys DROP CONSTRAINT subkeys_pk;`,
	`ALTER TABLE subkeys DROP CONSTRAINT subkeys_fk;`,
	`DROP INDEX subkeys_rfp;`,
}

/// AYAKU

const BLOCKCH_VERBOSE = 1

func ScanBlockchain(stor hkpstorage.Storage) (err error) {
	/*const (
		host   = "localhost"
		port   = 5432
		user   = "hkptest"
		dbname = "hkp"
	)
	psqlInfo := fmt.Sprintf("host=%s port=%d user=%s "+
		"password=%s dbname=%s sslmode=disable", //password=%s
		host, port, user, "ira", dbname)
	//fmt.Printf("Connection string : %s\n", psqlInfo)
	//psqlInfo := fmt.Sprintf("dbname=hkp sslmode=disable")
	scandb, err := sql.Open("postgres", psqlInfo)
	if err != nil {
		fmt.Println(err)
		return err
	}
	defer scandb.Close()

	err = scandb.Ping()
	if err != nil {
		fmt.Println(err)
		return err
	}*/

	for {
		time.Sleep(30 * time.Second)

		// map hex.EncodeToString(finger) -> bool (Cert with Finger in Storage isEqual to one of the Armoured cert in History (Eth Events))
		mIsEqual := make(map[string]bool)

		announceEvents, err := GetCertAnnounces()
		if err != nil {
			fmt.Printf("ERROR IN Announce Collection: %v\n", err)
			return err
		}

		for _, event := range announceEvents {
			if BLOCKCH_VERBOSE > 0 {
				strCertMD5, err := calcArmoredMD5(event.Armoured)
				if err != nil {
					return errors.New(fmt.Sprintf("ERROR IN MD5 calc of armoured cert for Finger %x: %v\n",
						event.Finger, err))
				}
				fmt.Printf("Starting proc of event with code=%v, finger=%x, armoured Len=%v, cert md5= %v\n",
					event.Code.Int64(), event.Finger, len(event.Armoured), strCertMD5)
			}
			isEqual, _ /*wasFound*/ := mIsEqual[hex.EncodeToString(event.Finger)]
			if isEqual == true {
				continue
			}
			// isFoundAndEqual = 1 if equal, 0 if found and not equal, -1 if not found
			isFoundAndEqual, err := IsFingerFoundAndEqualArmoured(event.Finger, event.Armoured, stor)
			if err != nil {
				return errors.New(fmt.Sprintf("ERROR IN Announce Processing (Equals and Found) for Finger %x: %v\n",
					event.Finger, err))
			}

			if isFoundAndEqual == -1 {
				// Finger is Not Found in storage
				primKey, err := parseArmored(event.Armoured)
				if err != nil {
					return errors.New(fmt.Sprintf("ERROR IN Announce Armoured Parsing for Finger %x: %v\n",
						event.Finger, err))
				}
				_, err = stor.Insert([]*openpgp.PrimaryKey{&primKey})
				if err != nil {
					return errors.New(fmt.Sprintf("ERROR IN Announce Armoured INSERT for Finger %x: %v\n",
						event.Finger, err))
				}
				mIsEqual[hex.EncodeToString(event.Finger)] = true
			}

			if isFoundAndEqual == 1 {
				// cert with the Finger equals to the current cert (one of those) in the history of announced
				mIsEqual[hex.EncodeToString(event.Finger)] = true
			}

			if isFoundAndEqual == 0 {
				// cert with the Finger does not equal to the current cert (one of those) in the history of announced
				_ /*isEqual*/, isFound := mIsEqual[hex.EncodeToString(event.Finger)]
				if isFound == false {
					mIsEqual[hex.EncodeToString(event.Finger)] = false
				}
			}

		}

		for strFinger, isEqual := range mIsEqual {
			if isEqual {
				continue
			}
			finger, err := hex.DecodeString(strFinger)
			if err != nil {
				return errors.New(fmt.Sprintf("ERROR in strFinger parsing of %s: %v\n",
					strFinger, err))
			}
			isNotFound, err := InsertEthFromStor(finger, stor)
			if err != nil {
				return errors.New(fmt.Sprintf("ERROR in INSERT Eth From Store for Finger %x: %v\n",
					finger, err))
			}
			if isNotFound {
				return errors.New(fmt.Sprintf("Not found key in storage for Finger %x\n", finger))
			}
		}
	}
}

/* returns in res:
 0 - not equal
 1 - equals
-1 - finger's key in storage is not found
*/
func IsFingerFoundAndEqualArmoured(finger []byte, armouredFromEth []byte,
	stor hkpstorage.Storage) (result int, err error) {

	//creating a new openpg.PrimaryKey based on armored string from blockchain.
	armouredPrimKey, err := parseArmored(armouredFromEth)
	if err != nil {
		return 0, errors.New(fmt.Sprintf("Cannnot parse armoured cert from Eth for %s: %v\n",
			hex.EncodeToString(finger), err))
	}

	//receiving certificate from storage corresponding to the finger
	var rFingers []string
	rFingers = append(rFingers, openpgp.Reverse(hex.EncodeToString(finger)))
	arrPrimaKey, err := stor.FetchKeys(rFingers)
	if len(arrPrimaKey) > 1 {
		return 0, errors.New(fmt.Sprintf("Too many records corresponding to finger %s\n", hex.EncodeToString(finger)))
	}
	if len(arrPrimaKey) == 0 {
		return -1, nil
	}

	storMD5hash, err := calcMD5(arrPrimaKey[0])
	if err != nil {
		return 0, errors.New(fmt.Sprintf("Calc of storaged cert MD5 for finger %s: %v\n",
			hex.EncodeToString(finger), err))
	}
	ethMD5hash, err := calcMD5(&armouredPrimKey)
	if err != nil {
		return 0, errors.New(fmt.Sprintf("Calc of ethereum extracted armoured cert MD5 for finger %s: %v\n",
			hex.EncodeToString(finger), err))
	}
	if storMD5hash == ethMD5hash {
		// certificates are the same - return of 1
		return 1, nil
	}
	return 0, nil
}

/*
func ProcPotentialChange(finger []byte, armouredFromEth []byte, code *big.Int, stor hkpstorage.Storage) (err error) {
	//creating a new openpg.PrimaryKey based on armored string from blockchain.
	ethPrimKey, err := parseArmored(armouredFromEth)
	if err != nil {
		return errors.New(fmt.Sprintf("Cannnot parse armoured cert from Eth for %s: %v\n",
			hex.EncodeToString(finger), err))
	}

	//receiving certificate from storage corresponding to the finger
	var rFingers []string
	rFingers = append(rFingers, openpgp.Reverse(hex.EncodeToString(finger)))
	arrPrimaKey, err := stor.FetchKeys(rFingers)
	if len(arrPrimaKey) > 1 {
		return errors.New(fmt.Sprintf("Too many records corresponding to finger %s\n", hex.EncodeToString(finger)))
	}
	if len(arrPrimaKey) == 1 {
		// POTENTIAL UPDATE arrPrimaKey[0] Here we should provide pgp cert and compare hashes
		storMD5hash, err := calcMD5(arrPrimaKey[0])
		if err != nil {
			return errors.New(fmt.Sprintf("Calc of storaged cert MD5 for finger %s: %v\n",
				hex.EncodeToString(finger), err))
		}
		ethMD5hash, err := calcMD5(&ethPrimKey)
		if err != nil {
			return errors.New(fmt.Sprintf("Calc of ethereum extracted armoured cert MD5 for finger %s: %v\n",
				hex.EncodeToString(finger), err))
		}
		if storMD5hash == ethMD5hash {
			// certificates are the same - no update needed
			fmt.Printf("DEBUG: certificates are the same for %s - no update needed\n")
			return nil
		}
	}

	if len(arrPrimaKey) == 0 {
		// ADD THE NEW CERT HERE -- THIS NEVER WORKS DUE TO RESTRICTION ABOVE
		_, err = stor.Insert([]*openpgp.PrimaryKey{&arrEthCert[0]})
		if err != nil {
			return errors.New(fmt.Sprintf("Cannot Insert Eth cert fp=%s -- %s", finger, err))
		}
	} else {
		// UPDATE IS HERE
		err = stor.Update(&arrEthCert[0], "")
		if err != nil {
			return errors.New(fmt.Sprintf("Cannot Update Eth cert fp=%s -- %s", finger, err))
		}
	}
	return nil
}
*/
/// !AYAKU

// Dial returns PostgreSQL storage connected to the given database URL.
func Dial(url string) (hkpstorage.Storage, error) {
	db, err := sql.Open("postgres", url)
	if err != nil {
		return nil, errgo.Mask(err)
	}

	/// AYAKU
	//return New(db)
	stor, err := New(db)
	if err != nil {
		return nil, errgo.Mask(err)
	}
	err = LoadConfig() //ethereum configuration
	if err != nil {
		fmt.Printf("ERROR IN ETHEREUM CONFIG LOAD: %v\n", err)
		os.Exit(1)
	}
	go ScanBlockchain(stor)

	return stor, nil
	/// !AYAKU
}

// New returns a PostgreSQL storage implementation for an HKP service.
func New(db *sql.DB) (hkpstorage.Storage, error) {
	st := &storage{
		DB: db,
	}
	err := st.createTables()
	if err != nil {
		return nil, errgo.Mask(err)
	}
	st.createIndexes()
	return st, nil
}

func (st *storage) createTables() error {
	for _, crTableSQL := range crTablesSQL {
		_, err := st.Exec(crTableSQL)
		if err != nil {
			return errgo.Mask(err)
		}
	}
	return nil
}

func (st *storage) createIndexes() {
	for _, crIndexSQL := range crIndexesSQL {
		_, err := st.Exec(crIndexSQL)
		if err != nil {
			log.Warningf("error executing %q: %v", crIndexSQL, err)
		}
	}
}

type keyDoc struct {
	RFingerprint string
	CTime        time.Time
	MTime        time.Time
	MD5          string
	Doc          string
	Keywords     []string
}

func (st *storage) MatchMD5(md5s []string) ([]string, error) {
	var md5In []string
	for _, md5 := range md5s {
		// Must validate to prevent SQL injection since we're appending SQL strings here.
		_, err := hex.DecodeString(md5)
		if err != nil {
			return nil, errgo.Notef(err, "invalid MD5 %q", md5)
		}
		md5In = append(md5In, "'"+strings.ToLower(md5)+"'")
	}

	sqlStr := fmt.Sprintf("SELECT rfingerprint FROM keys WHERE md5 IN (%s)", strings.Join(md5In, ","))
	rows, err := st.Query(sqlStr)
	if err != nil {
		return nil, errgo.Mask(err)
	}

	var result []string
	defer rows.Close()
	for rows.Next() {
		var rfp string
		err := rows.Scan(&rfp)
		if err != nil && err != sql.ErrNoRows {
			return nil, errgo.Mask(err)
		}
		result = append(result, rfp)
	}
	err = rows.Err()
	if err != nil {
		return nil, errgo.Mask(err)
	}
	return result, nil
}

// Resolve implements storage.Storage.
//
// Only v4 key IDs are resolved by this backend. v3 short and long key IDs
// currently won't match.
func (st *storage) Resolve(keyids []string) (_ []string, retErr error) {
	var result []string
	sqlStr := "SELECT rfingerprint FROM keys WHERE rfingerprint LIKE $1 || '%'"
	stmt, err := st.Prepare(sqlStr)
	if err != nil {
		return nil, errgo.Mask(err)
	}
	defer stmt.Close()

	var subKeyIDs []string
	for _, keyid := range keyids {
		keyid = strings.ToLower(keyid)
		if len(keyid) < maxFingerprintLen {
			var rfp string
			row := stmt.QueryRow(keyid)
			err = row.Scan(&rfp)
			if err == sql.ErrNoRows {
				subKeyIDs = append(subKeyIDs, keyid)
			} else if err != nil {
				return nil, errgo.Mask(err)
			}
			result = append(result, rfp)
		} else {
			result = append(result, keyid)
		}
	}

	if len(subKeyIDs) > 0 {
		subKeyResult, err := st.resolveSubKeys(subKeyIDs)
		if err != nil {
			return nil, errgo.Mask(err)
		}
		result = append(result, subKeyResult...)
	}

	return result, nil
}

func (st *storage) resolveSubKeys(keyids []string) ([]string, error) {
	var result []string
	sqlStr := "SELECT rfingerprint FROM subkeys WHERE rsubfp LIKE $1 || '%'"
	stmt, err := st.Prepare(sqlStr)
	if err != nil {
		return nil, errgo.Mask(err)
	}
	defer stmt.Close()

	for _, keyid := range keyids {
		keyid = strings.ToLower(keyid)
		if len(keyid) < maxFingerprintLen {
			var rfp string
			row := stmt.QueryRow(keyid)
			err = row.Scan(&rfp)
			if err != nil && err != sql.ErrNoRows {
				return nil, errgo.Mask(err)
			}
			result = append(result, rfp)
		} else {
			result = append(result, keyid)
		}
	}

	return result, nil
}

func (st *storage) MatchKeyword(search []string) ([]string, error) {
	var result []string
	stmt, err := st.Prepare("SELECT rfingerprint FROM keys WHERE keywords @@ to_tsquery($1) LIMIT $2")
	if err != nil {
		return nil, errgo.Mask(err)
	}
	defer stmt.Close()

	for _, term := range search {
		term = strings.Join(strings.Split(strings.ToLower(term), " "), " & ")
		err = func() error {
			rows, err := stmt.Query(term, 100)
			if err != nil {
				return errgo.Mask(err)
			}
			defer rows.Close()
			for rows.Next() {
				var rfp string
				err = rows.Scan(&rfp)
				if err != nil && err != sql.ErrNoRows {
					return errgo.Mask(err)
				}
				result = append(result, rfp)
			}
			err = rows.Err()
			if err != nil {
				return errgo.Mask(err)
			}
			return nil
		}()
		if err != nil {
			return nil, err
		}
	}
	return result, nil
}

func (st *storage) ModifiedSince(t time.Time) ([]string, error) {
	var result []string
	rows, err := st.Query("SELECT rfingerprint FROM keys WHERE mtime > $1 ORDER BY mtime DESC LIMIT 100", t.UTC())
	if err != nil {
		return nil, errgo.Mask(err)
	}
	defer rows.Close()
	for rows.Next() {
		var rfp string
		err = rows.Scan(&rfp)
		if err != nil && err != sql.ErrNoRows {
			return nil, errgo.Mask(err)
		}
		result = append(result, rfp)
	}
	err = rows.Err()
	if err != nil {
		return nil, errgo.Mask(err)
	}
	return result, nil
}

func (st *storage) FetchKeys(rfps []string) ([]*openpgp.PrimaryKey, error) {
	if len(rfps) == 0 {
		return nil, nil
	}

	var rfpIn []string
	for _, rfp := range rfps {
		_, err := hex.DecodeString(rfp)
		if err != nil {
			return nil, errgo.Notef(err, "invalid rfingerprint %q", rfp)
		}
		rfpIn = append(rfpIn, "'"+strings.ToLower(rfp)+"'")
	}
	sqlStr := fmt.Sprintf("SELECT doc FROM keys WHERE rfingerprint IN (%s)", strings.Join(rfpIn, ","))
	if BLOCKCH_VERBOSE > 1 {
		fmt.Printf("Fetching Keys -- %s\n", sqlStr)
	}
	rows, err := st.Query(sqlStr)
	if err != nil {
		return nil, errgo.Mask(err)
	}

	var result []*openpgp.PrimaryKey
	for rows.Next() {
		var bufStr string
		err = rows.Scan(&bufStr)
		if err != nil && err != sql.ErrNoRows {
			return nil, errgo.Mask(err)
		}
		if BLOCKCH_VERBOSE > 1 {
			fmt.Printf("Retrieved in Fetching Keys -- %s\n", bufStr)
		}
		var pk jsonhkp.PrimaryKey
		err = json.Unmarshal([]byte(bufStr), &pk)
		if err != nil {
			return nil, errgo.Mask(err)
		}

		rfp := openpgp.Reverse(pk.Fingerprint)
		key, err := readOneKey(pk.Bytes(), rfp)
		if err != nil {
			return nil, errgo.Mask(err)
		}
		result = append(result, key)
	}
	err = rows.Err()
	if err != nil {
		return nil, errgo.Mask(err)
	}

	return result, nil
}

func (st *storage) FetchKeyrings(rfps []string) ([]*hkpstorage.Keyring, error) {
	var rfpIn []string
	for _, rfp := range rfps {
		_, err := hex.DecodeString(rfp)
		if err != nil {
			return nil, errgo.Notef(err, "invalid rfingerprint %q", rfp)
		}
		rfpIn = append(rfpIn, "'"+strings.ToLower(rfp)+"'")
	}
	sqlStr := fmt.Sprintf("SELECT ctime, mtime, doc FROM keys WHERE rfingerprint IN (%s)", strings.Join(rfpIn, ","))
	rows, err := st.Query(sqlStr)
	if err != nil {
		return nil, errgo.Mask(err)
	}

	var result []*hkpstorage.Keyring
	for rows.Next() {
		var bufStr string
		var kr hkpstorage.Keyring
		err = rows.Scan(&bufStr, &kr.CTime, &kr.MTime)
		if err != nil && err != sql.ErrNoRows {
			return nil, errgo.Mask(err)
		}
		var pk jsonhkp.PrimaryKey
		err = json.Unmarshal([]byte(bufStr), &pk)
		if err != nil {
			return nil, errgo.Mask(err)
		}

		rfp := openpgp.Reverse(pk.Fingerprint)
		key, err := readOneKey(pk.Bytes(), rfp)
		if err != nil {
			return nil, errgo.Mask(err)
		}
		kr.PrimaryKey = key
		result = append(result, &kr)
	}
	err = rows.Err()
	if err != nil {
		return nil, errgo.Mask(err)
	}

	return result, nil
}

func readOneKey(b []byte, rfingerprint string) (*openpgp.PrimaryKey, error) {
	c := openpgp.ReadKeys(bytes.NewBuffer(b))
	defer func() {
		for _ = range c {
		}
	}()
	var result *openpgp.PrimaryKey
	for readKey := range c {
		if readKey.Error != nil {
			return nil, errgo.Mask(readKey.Error)
		}
		if result != nil {
			return nil, errgo.Newf("multiple keys in keyring: %v, %v", result.Fingerprint(), readKey.Fingerprint())
		}
		if readKey.PrimaryKey.RFingerprint != rfingerprint {
			return nil, errgo.Newf("RFingerprint mismatch: expected=%q got=%q",
				rfingerprint, readKey.PrimaryKey.RFingerprint)
		}
		result = readKey.PrimaryKey
	}
	return result, nil
}

func (st *storage) Insert(keys []*openpgp.PrimaryKey) (n int, retErr error) {
	if BLOCKCH_VERBOSE > 0 {
		fmt.Println("Entering Insert procedure of Hockeypuck storage (Postgres) ...")
	}

	tx, err := st.Begin()
	if err != nil {
		return 0, errgo.Mask(err)
	}
	defer func() {
		if retErr != nil {
			tx.Rollback()
		} else {
			tx.Commit()
		}
	}()

	stmt, err := tx.Prepare("INSERT INTO keys (rfingerprint, ctime, mtime, md5, doc, keywords) " +
		"SELECT $1::TEXT, $2::TIMESTAMP, $3::TIMESTAMP, $4::TEXT, $5::JSONB, to_tsvector($6) " +
		"WHERE NOT EXISTS (SELECT 1 FROM keys WHERE rfingerprint = $1)")
	if err != nil {
		return 0, errgo.Mask(err)
	}
	defer stmt.Close()

	subStmt, err := tx.Prepare("INSERT INTO subkeys (rfingerprint, rsubfp) " +
		"SELECT $1::TEXT, $2::TEXT WHERE NOT EXISTS (SELECT 1 FROM subkeys WHERE rsubfp = $2)")
	if err != nil {
		return 0, errgo.Mask(err)
	}
	defer subStmt.Close()

	var certContent bytes.Buffer
	if err != nil {
		fmt.Printf("insert -- cannot generate cert: %s\n", err)
	}
	err = openpgp.WriteArmoredPackets(&certContent, keys)
	if err != nil {
		fmt.Printf("CHECKUP TO DEL -- cannot generate armored cert\n")
	}

	var result hkpstorage.InsertError
	for _, key := range keys {
		openpgp.Sort(key)

		//AYAKU
		if BLOCKCH_VERBOSE > 0 {
			fmt.Println("Staring Insert into Ethereum procedure ...")
		}

		err := InsertEth(key)
		if err != nil {
			result.Errors = append(result.Errors, errgo.Notef(err, "Error in InsertEth fp=%s - %s",
				key.Fingerprint()), err)
			fmt.Printf("Error in InsertEth fp=%s - %s\n", key.Fingerprint(), err)
		}
		//!AYAKU

		now := time.Now().UTC()
		jsonKey := jsonhkp.NewPrimaryKey(key)
		jsonBuf, err := json.Marshal(jsonKey)
		if err != nil {
			result.Errors = append(result.Errors, errgo.Notef(err, "cannot serialize rfp=%q", key.RFingerprint))
			fmt.Println("insert error -- cannot serialize")
			continue
		}

		jsonStr := string(jsonBuf)
		keyword := strings.Join(keywords(key), " & ")

		_, err = stmt.Exec(&key.RFingerprint, &now, &now, &key.MD5, &jsonStr, &keyword)
		if err != nil {
			result.Errors = append(result.Errors, errgo.Notef(err, "cannot insert rfp=%q", key.RFingerprint))
			continue
		}
		for _, subKey := range key.SubKeys {
			_, err = subStmt.Exec(&key.RFingerprint, &subKey.RFingerprint)
			if err != nil {
				result.Errors = append(result.Errors, errgo.Notef(err, "cannot insert rsubfp=%q", subKey.RFingerprint))
			}
		}
		st.Notify(hkpstorage.KeyAdded{
			Digest: key.MD5,
		})
		n++
	}

	if len(result.Duplicates) > 0 || len(result.Errors) > 0 {
		return n, result
	}
	return n, nil
}

//AYAKU

func InsertEthFromStor(finger []byte, stor hkpstorage.Storage) (isNotFoundInStor bool, err error) {
	//receiving certificate from storage corresponding to the finger
	var rFingers []string
	rFingers = append(rFingers, openpgp.Reverse(hex.EncodeToString(finger)))
	arrPrimaKey, err := stor.FetchKeys(rFingers)
	if len(arrPrimaKey) > 1 {
		return false,
			errors.New(fmt.Sprintf("Too many records corresponding to finger %s\n", hex.EncodeToString(finger)))
	}
	if len(arrPrimaKey) == 0 {
		return true,
			errors.New(fmt.Sprintf("Too many records corresponding to finger %s\n", hex.EncodeToString(finger)))
	}

	err = InsertEth(arrPrimaKey[0])
	if err != nil {
		return false, errors.New(fmt.Sprintf("Error in InsertEth fp=%x - %s\n", finger, err))
	}
	return false, nil
}

func InsertEth(key *openpgp.PrimaryKey) (err error) {
	var arrKeywords []string
	for _, keyId := range key.UserIDs {
		arrKeywords = append(arrKeywords, keyId.Keywords)
	}
	if BLOCKCH_VERBOSE > 0 {
		fmt.Printf("InsertEth starting: keyword = %v\n", arrKeywords)
	}
	isBlockchain, _ /* ethAddr */, err := getEthAddrKeywords(arrKeywords)
	if err != nil {
		return errors.New(fmt.Sprintf("Error in getEthAddrKeywords fp=%s - %s\n", key.Fingerprint(), err))
	}
	if isBlockchain {
		newMD5, err := calcMD5(key)
		if err != nil {
			return errors.New(fmt.Sprintf("Calculating MD5 of certificate for finger %s: %v\n",
				key.Fingerprint(), err))
		}
		if BLOCKCH_VERBOSE > 0 {
			fmt.Printf("InsertEth: isBlockchain, cert MD5=%v\n", newMD5)
		}
		wasAnounced, err := WasCertAnnouncedEth(key.Fingerprint(), newMD5)
		if err != nil {
			return errors.New(fmt.Sprintf("Error in WasCertAnnouncedEth fp=%s - %s\n", key.Fingerprint(), err))
		}
		if BLOCKCH_VERBOSE > 0 {
			fmt.Printf("InsertEth was certificate nnounced = %v\n", wasAnounced)
		}
		if !wasAnounced {
			certContent, err := GenerateCertContent(key)
			if err != nil {
				return errors.New(fmt.Sprintf("Insert -- cannot generate cert for finger %s: %s\n",
					key.Fingerprint(), err))
			}

			fmt.Printf("DEBUG: Inserting into Eth the certificate %s:\n%s\n", key.Fingerprint(), certContent.String())
			err = ActionCertEth("", key.Fingerprint(), certContent.String(), CERTACT_LOAD)
			if err != nil {
				return errors.New(fmt.Sprintf("insert -- error ethereum: %s\n", err))
			}
		}
	}
	return nil
}

// Receives the list of cert hashes (md5) announced in Ethereum
func GetCertMD5AnnouncedEth(strFinger string) (arrHashes []string, err error) {
	finger, err := hex.DecodeString(strFinger)
	if err != nil {
		return arrHashes, errors.New(fmt.Sprintf("Failed to convert finger str %s to bytes: %v", strFinger, err))
	}

	events, err := GetCertAnnounces()
	for _, event := range events {
		if string(event.Finger) != string(finger) {
			continue // this is another finger
		}
		md5, err := calcArmoredMD5(event.Armoured)
		if err != nil {
			return arrHashes, errors.New(fmt.Sprintf("Parsing announed Armoured : %v", err))
		}
		arrHashes = append(arrHashes, md5)
	}
	return arrHashes, nil
}

func WasCertAnnouncedEth(finger string, hashMD5 string) (wasAnnouced bool, err error) {
	arrHashes, err := GetCertMD5AnnouncedEth(finger)
	if err != nil {
		return false, err
	}
	fmt.Printf("Was Cert Announced = list of announced: %v\n", arrHashes)
	for _, hash := range arrHashes {
		if hash == hashMD5 {
			return true, nil
		}
	}
	return false, nil
}

func GenerateCertContent(primKey *openpgp.PrimaryKey) (certContent bytes.Buffer, err error) {
	tmpKeys := make([]*openpgp.PrimaryKey, 1)
	tmpKeys[0] = primKey
	err = openpgp.WriteArmoredPackets(&certContent, tmpKeys)
	if err != nil {
		//result.Errors = append(result.Errors, errgo.Notef(err, "cannot generate armored cert rfp=%q", key.RFingerprint))
		return certContent, err
	}
	return certContent, nil
}

func calcArmoredMD5(armouredContent []byte) (strMD5 string, err error) {
	primKey, err := parseArmored(armouredContent)
	if err != nil {
		return "", errors.New(fmt.Sprintf("Cannot parse Eth cert %s", err))
	}
	return calcMD5(&primKey)
}
func parseArmored(armouredContent []byte) (primKey openpgp.PrimaryKey, err error) {
	chPgpCert, err := openpgp.ReadArmorKeys(bytes.NewReader(armouredContent))
	if err != nil {
		return primKey, errors.New(fmt.Sprintf("Cannot parse armoured cert %s", err))
	}
	var arrPgpCert []openpgp.PrimaryKey
	for pgpCert := range chPgpCert {
		arrPgpCert = append(arrPgpCert, *pgpCert.PrimaryKey)
	}
	if len(arrPgpCert) > 1 {
		return primKey, errors.New(fmt.Sprintf("Received more than 1 PGP cert from armorParse"))
	}
	if len(arrPgpCert) == 0 {
		return primKey, errors.New(fmt.Sprintf("Received 0 PGP cert from armorParse"))
	}
	return arrPgpCert[0], nil
}
func calcMD5(primKey *openpgp.PrimaryKey) (strMD5 string, err error) {
	strMD5, err = openpgp.SksDigest(primKey, md5.New())
	if err != nil {
		return "", err
	}
	return strMD5, nil
}

//!AYAKU

func (st *storage) Update(key *openpgp.PrimaryKey, lastMD5 string) (retErr error) {
	tx, err := st.Begin()
	if err != nil {
		return errgo.Mask(err)
	}
	defer func() {
		if retErr != nil {
			tx.Rollback()
		} else {
			tx.Commit()
		}
	}()

	openpgp.Sort(key)

	now := time.Now().UTC()
	jsonKey := jsonhkp.NewPrimaryKey(key)
	jsonBuf, err := json.Marshal(jsonKey)
	keyword := strings.Join(keywords(key), " & ")

	//AYAKU
	var arrKeywords []string
	for _, keyId := range key.UserIDs {
		arrKeywords = append(arrKeywords, keyId.Keywords)
	}
	isBlockchain, _ /* ethAddr */, err := getEthAddrKeywords(arrKeywords)
	if isBlockchain {
		var ethCertContent string
		err = PrintEth("" /*email*/, key.Fingerprint(), &ethCertContent, CERTPRNT_CERT)
		if err != nil {
			return errgo.Mask(errors.New(fmt.Sprintf("Cannot retrieve from Eth rfp=%q -- %s", key.RFingerprint, err)))
		}
		strMD5_newupd, err := calcMD5(key)
		if err != nil {
			return errgo.Mask(errors.New(fmt.Sprintf(
				"EthCertContent: Calc SHA256 (smart contract methodology) for finger %s: %v\n",
				key.Fingerprint(), err)))
		}
		strMD5_ethereum, err := calcArmoredMD5([]byte(ethCertContent))
		if err != nil {
			return errgo.Mask(errors.New(fmt.Sprintf(
				"EthCertContent: Calc SHA256 (smart contract methodology) for finger %s: %v\n",
				key.Fingerprint(), err)))
		}
		if strMD5_ethereum == strMD5_newupd {
			return errgo.Mask(errors.New(fmt.Sprintf("Eth certificate equals new cert, rfp=%q -- cert %s",
				key.RFingerprint, strMD5_ethereum)))
		}
		if strMD5_ethereum != lastMD5 {
			return errgo.Mask(errors.New(fmt.Sprintf(
				"Eth certificate (MD5 = %s) does not equal previous cert (MD5 = %s), rfp=%q",
				strMD5_ethereum, lastMD5, key.RFingerprint)))
		}

		generCert, err := GenerateCertContent(key)
		if err != nil {
			return errgo.Mask(errors.New(fmt.Sprintf(
				"GenerateCertContent: error for finger %s: %v\n", key.Fingerprint(), err)))
		}

		err = ActionCertEth("", key.Fingerprint(), generCert.String(), CERTACT_LOAD)
		if err != nil {
			return errgo.Mask(errors.New(fmt.Sprintf("Cannot store to Eth rfp=%q -- %s", key.RFingerprint, err)))
		}
	}
	//!AYAKU

	_, err = tx.Exec("UPDATE keys SET mtime = $1, md5 = $2, keywords = to_tsvector($3), doc = $4 "+
		"WHERE rfingerprint = $5",
		&now, &key.MD5, &keyword, jsonBuf, &key.RFingerprint)
	if err != nil {
		return errgo.Mask(err)
	}
	for _, subKey := range key.SubKeys {
		_, err := tx.Exec("INSERT INTO subkeys (rfingerprint, rsubfp) "+
			"SELECT $1::TEXT, $2::TEXT WHERE NOT EXISTS (SELECT 1 FROM subkeys WHERE rsubfp = $2)",
			&key.RFingerprint, &subKey.RFingerprint)
		if err != nil {
			return errgo.Mask(err)
		}
	}

	st.Notify(hkpstorage.KeyReplaced{
		OldDigest: lastMD5,
		NewDigest: key.MD5,
	})
	return nil
}

// keywords returns a slice of searchable tokens extracted
// from the given UserID packet keywords string.
func keywords(key *openpgp.PrimaryKey) []string {
	m := make(map[string]bool)
	for _, uid := range key.UserIDs {
		s := strings.ToLower(uid.Keywords)
		lbr, rbr := strings.Index(s, "<"), strings.LastIndex(s, ">")
		if lbr != -1 && rbr > lbr {
			m[s[lbr+1:rbr]] = true
		}
		if lbr != -1 {
			fields := strings.FieldsFunc(s[:lbr], func(r rune) bool {
				if !utf8.ValidRune(r) {
					return true
				}
				if unicode.IsLetter(r) || unicode.IsNumber(r) {
					return false
				}
				return true
			})
			for _, field := range fields {
				m[field] = true
			}
		}
	}
	var result []string
	for k := range m {
		result = append(result, k)
	}
	return result
}

func subkeys(key *openpgp.PrimaryKey) []string {
	var result []string
	for _, subkey := range key.SubKeys {
		result = append(result, subkey.RFingerprint)
	}
	return result
}

func (st *storage) Subscribe(f func(hkpstorage.KeyChange) error) {
	st.mu.Lock()
	st.listeners = append(st.listeners, f)
	st.mu.Unlock()
}

func (st *storage) Notify(change hkpstorage.KeyChange) error {
	st.mu.Lock()
	defer st.mu.Unlock()
	log.Debugf("%v", change)
	for _, f := range st.listeners {
		// TODO: log error notifying listener?
		f(change)
	}
	return nil
}

func (st *storage) RenotifyAll() error {
	sqlStr := fmt.Sprintf("SELECT md5 FROM keys")
	rows, err := st.Query(sqlStr)
	if err != nil {
		return errgo.Mask(err)
	}

	defer rows.Close()
	for rows.Next() {
		var md5 string
		err := rows.Scan(&md5)
		if err != nil {
			if err == sql.ErrNoRows {
				return nil
			} else {
				return errgo.Mask(err)
			}
		}
		st.Notify(hkpstorage.KeyAdded{Digest: md5})
	}
	err = rows.Err()
	return errgo.Mask(err)
}
