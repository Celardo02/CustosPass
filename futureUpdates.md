# Future Updates

This file contains the features that I plan to implement in the future, organized by area of interest.

## Table of Contents

- [Login](#login) 
- [Credential Sets](#credential-sets)
- [Miscellaneous](#miscellaneous)

## Login

- **Password recovery support**: since no remote server is involved, no password recovery procedure is currently implemented. In order to get this feature, a backup password may be specified during vault initialization: users will be able to set an additional password (called _recovery password_) that will securely store the master password through encryption. The recovery password will only be used if the maste password is lost
- **Adding MFA**: multi-factor authentication will be added to enhance security. Incremental delays will be implemented to prevent brute-force attacks 

## Credential Sets 

- **custom labels**: currently, credential sets are not grouped in any way. Users will be able to organize credential sets in groups, depending on the labels of each credentail set.
- **custom labels**: currently, credential sets are not grouped in any way. Users will be able to organize credential sets in groups, depending on the labels of each credentail set.
- **Custom expiration time**: currently, each credential set password has a fixed expiration time. Users will be able to customize it 
- **Password copy authorization**: additional requirements may be enforced before allowing a password to be copied from the vault. Users will be able to opt-in to be asked to re-enter the master password for each password copy.
- **Showing _free text_ and _password_ in plain text**: similar behavior as in _password copy authorization_ will be required before displaying _free text_ or _password_ fields in plain text
- **Auotmatic password typing**: instead of copying and pasting credential sets' password, users will be able to start the auto-type functionality and then select the text box to be filled in

## Miscellaneous

- **Multi-language support**
