# CustosPass Requirements

This file contains all the functional and non-functional requirements of the CustosPass password manager project.

# Table of contents

- [1 Functional Requirements](#1-functional-requirements)
    - [1.1 Passwords](#11-passwords)
    - [1.2 Credential Sets](#12-credential-sets)
    - [1.3 User Interfaces](#13-user-interfaces)
        - [1.3.1 Login](#131-login)
        - [1.3.2 Credential Sets Handling](#132-credential-sets-handling)
        - [1.3.3 Master Password Handling](#133-master-password-handling)
        - [1.3.4 Synchronization Handling](#134-synchronization-handling)
    - [1.4 Vault Storing](#14-vault-storing)
    - [1.5 Miscellaneous](#15-miscellaneous)
- [2 Non-Functional Requirements](#2-non-functional-requirements)
    - [2.1 Encryption Algorithms Requirements](#21-encryption-algorithms-requirements)
    - [2.2 Master Password Security](#22-master-password-security)
    - [2.3 User Interfaces Security](#23-user-interfaces-security)
        - [2.3.1 Login Security](#231-login-security)
        - [2.3.2 Credential Sets Handling Security](#232-credential-sets-handling-security)
        - [2.3.3 Synchronization Security](#233-synchronization-security)
    - [2.4 Vault Security](#24-vault-security)
    - [2.5 Other Security Features](#25-other-security-features)

# 1 Functional Requirements

## 1.1 Passwords

Each credential set's password and the master password must:
1. be at least 10 characters long
2. contain at least:
    1. a capital letter
    2. a lowercase letter
    3. a number
    4. a special character from the following:
        - ``-``
        - ``+``
        - ``_``
        - ``&``
        - ``%``
        - ``@``
        - ``$``
        - ``?``
        - ``!``
        - ``#``
3. expire after 3 months by default
    1. a warning must be shown upon each login if the password is expired
    2. the user must be able to ignore the warning
    3. the user must be able to flag any password but the master one as _never expiring_

## 1.2 Credential Sets

Each credential set must have:
1. a unique ID
2. a password that complies with each requirement in [Passwords](#passwords) section. The password must be typed by the user or automatically generated
3. _optional_ fields:
    1. username
    2. e-mail
    3. free text, allowing any kind of note
    4. user-defined labels

## 1.3 User Interfaces

### 1.3.1 Login

Login interface must allow the user to:
1. initialize a new vault, if and only if the vault does not exist yet
2. import a vault from another device, if and only if the vault does not exist yet
    1. both previous and newly imported vault master passwords must be provided and verified
3. type in the master password to login, if and only if the vault exists
    1. typed password must be checked
4. delete the existing vault
    1. the master password must be provided

### 1.3.2 Credential Sets Handling

Credential sets handling interface must allow the user to:
1. add a new credential set
    1. master password must be provided
2. copy a credential set's password to the clipboard
3. edit any field of each credential set and save those changes
    1. master password must be provided
4. delete a credential set
    1. master password must be provided
5. receive warnings for credential sets whose passwords are expired
6. receive warnings for credential sets whose passwords are flagged as _never expiring_
7. see all credential sets inside the vault. Only the following fields must be always shown:
    - ID
    - e-mail (this field must be empty if the e-mail does not exist)
    - username (this field must be empty if the username does not exist)
    - expiration date/warning
Plain text password and free text fields must be shown on user demand
8. search for one or more credential sets by typing a string that may appear in the ID, username and/or e-mail fields
9. group credential sets by a specific label
10. order credential sets by ID, username, e-mail or expiration date


### 1.3.3 Master Password Handling

Master password handling interface must:
1. show the expiration date of the master password
2. allow the user to change the master password
    1. the old master password must be provided
    2. the new master password must be typed two times. The new master password must be approved if and only if both entries are identical 
    3. vault must be decrypted and then encrypted with the newer master password
3. warn the user with an ad hoc icon and message if the master password is expired

### 1.3.4 Synchronization Handling

Synchronization handling interface must allow the user to:
1. send its own vault to another device
    1. the master password must be provided
2. receive a vault from another device
    1. this operation must overwrite the existing vault


## 1.4 Vault Storing

1. vault data must be stored in a file
2. the vault file must be updated every time a change is made to the vault data
3. the vault file must be read at each startup to load its content
4. the user must be able to export a copy of the vault to a desired position in the file system

## 1.5 Miscellaneous

1. the user must be able to log out



# 2 Non-Functional Requirements

## 2.1 Encryption Algorithms Requirements

1. PBKDF2 will be used as the key derivation and hash function
    1. salt value must be unique
    2. HMAC-SHA512 must be used as hash algorithm ([OWASP advice](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#pbkdf2))
2. symmetric encryption will be performed using AES GCM algorithm
    1. the encryption key must be the output of the key derivation algorithm applied to the chosen password and a newly generated salt
    2. inizialization vector must be unique

Each time that one of those algorithms is cited in the text below, its requirements must be enforced.


## 2.2 Master Password Security

Master password must be:
1. stored as its corresponding hash
2. different from previous ones, if changed
    1. old master passwords must be stored as their hashes
3. checked each time it is provided 

## 2.3 User Interfaces Security

### 2.3.1 Login Security

1. incremental delay time must take place for each failed login attempt. Mandatory delays:
    - first three errors: no delay time
    - fourth error: 5 seconds
    - from fifth error onward: previous attempt delay time multiplied by four

### 2.3.2 Credential Sets Handling Security

1. clipboard must be overwritten with random data or physically erased after 30 seconds when copying a password

### 2.3.3 Synchronization Security

1. peer-to-peer communication during vault synchronization operations must use TLS 1.3 to 
exchange any information
2. a timestamp must be included within the AES additional authenticated data (AAD) 
    1. any vault sent more than one minute before the time of receipt must be ignored 
3. the sender must generate a random OTP (called _vault tag_ for simplicity) for each communication
    1. vault tag must be a 6-character alphanumeric string
    2. vault tag must be part of AES AAD
The vault tag will allow the user to quickly check whether the vault version he is importing is the correct one or not


## 2.4 Vault Security

1. vault file must be encrypted using the master password as an AES key
    1. the following data must be stored in plain text:
        1. master password hash and salt
        2. KDF function salt, AES initialization vector and AES tag used to compute vault encryption
    2. already used salt values, initialization vectors, old synchronization AES OTPs, old vault tags, and old master passwords must be stored inside the vault
2. vault integrity must be checked before importing its content inside the application
    1. content loading operation must be stopped, if vault integrity has been compromised
    2. user must be warned, if vault integrity has been compromised
3. the user must be able to export the vault:
    1. encrypted with its master password
    2. encrypted with a different master password. The new master password must be provided or automatically generated, depending on user choice
    3. as a plain text file. This option must be discouraged and used if and only if the user accepts handling handling data encryption on their own
    4. the master password must be provided in all previous cases

## 2.5 Other Security Features

1. the user must be logged out after 2 minutes of inactivity 
