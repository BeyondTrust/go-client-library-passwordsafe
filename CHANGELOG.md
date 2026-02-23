# Changelog

### [1.1.0](https://github.com/BeyondTrust/go-client-library-passwordsafe/compare/v1.0.0...v1.1.0) / 2026-02-23

#### Features

* [BIPS-33206] retrieve full token response with expiry info ([#293](https://github.com/BeyondTrust/go-client-library-passwordsafe/issues/293))

### [1.0.0](https://github.com/BeyondTrust/go-client-library-passwordsafe/compare/v0.25.0...v1.0.0) / 2025-12-29

#### ⚠ BREAKING CHANGES

* add support for decrypt parameter on get secret by path endpoint ([#290](https://github.com/BeyondTrust/go-client-library-passwordsafe/issues/290))

#### Features

* add support for decrypt parameter on get secret by path endpoint ([#290](https://github.com/BeyondTrust/go-client-library-passwordsafe/issues/290))

### [0.25.0](https://github.com/BeyondTrust/go-client-library-passwordsafe/compare/v0.24.0...v0.25.0) / 2025-11-19

#### Features

* add search secret by title method ([#280](https://github.com/BeyondTrust/go-client-library-passwordsafe/issues/280))

### [0.24.0](https://github.com/BeyondTrust/go-client-library-passwordsafe/compare/v0.23.0...v0.24.0) / 2025-11-13

#### Features

* move/add common methods from ESO repo to Go client library ([#278](https://github.com/BeyondTrust/go-client-library-passwordsafe/issues/278))

### 0.23.0 / 2025-10-23

#### Features

* [BIPS-28460] Add delete methods for managed accounts, secrets and folders ([#266](https://github.com/BeyondTrust/go-client-library-passwordsafe/issues/266))
* [BIPS-28460] Release ready ([#267](https://github.com/BeyondTrust/go-client-library-passwordsafe/issues/267))
* [BIPS-28461] delete methods part2 ([#270](https://github.com/BeyondTrust/go-client-library-passwordsafe/issues/270))
* [BIPS-28461] Managed Systems and Functional Accounts delete methods ([#272](https://github.com/BeyondTrust/go-client-library-passwordsafe/issues/272))
* add api version parameter ([#180](https://github.com/BeyondTrust/go-client-library-passwordsafe/issues/180))
* add creating assets feature in terraform provider ([#199](https://github.com/BeyondTrust/go-client-library-passwordsafe/issues/199))
* add creating Databases feature in terraform provider ([#201](https://github.com/BeyondTrust/go-client-library-passwordsafe/issues/201))
* add creating folders feature in terraform provider ([#165](https://github.com/BeyondTrust/go-client-library-passwordsafe/issues/165))
* add creating Managed System feature associated with Assets ([#209](https://github.com/BeyondTrust/go-client-library-passwordsafe/issues/209))
* add creating Managed System feature associated with Databases ([#228](https://github.com/BeyondTrust/go-client-library-passwordsafe/issues/228))
* add creating Managed System feature associated with Workgroups ([#223](https://github.com/BeyondTrust/go-client-library-passwordsafe/issues/223))
* add creating safes feature in terraform provider ([#175](https://github.com/BeyondTrust/go-client-library-passwordsafe/issues/175))
* add creating Workgroups feature in terraform provider ([#196](https://github.com/BeyondTrust/go-client-library-passwordsafe/issues/196))
* Add Functional Account datasource and get functional accounts list resource in terraform provider ([#234](https://github.com/BeyondTrust/go-client-library-passwordsafe/issues/234))
* add fuzzing tests ([#171](https://github.com/BeyondTrust/go-client-library-passwordsafe/issues/171))
* add performance test ([#56](https://github.com/BeyondTrust/go-client-library-passwordsafe/issues/56))
* add support for API version (3.0, 3.1) in create credential, text and file features ([#246](https://github.com/BeyondTrust/go-client-library-passwordsafe/issues/246))
* add writing managed accounts feature in terraform provider ([#152](https://github.com/BeyondTrust/go-client-library-passwordsafe/issues/152))
* add writing secrets feature in terraform provider ([#161](https://github.com/BeyondTrust/go-client-library-passwordsafe/issues/161))
* BIPS-18112 Enforce PR link to Jira ([#147](https://github.com/BeyondTrust/go-client-library-passwordsafe/issues/147))
* Changing release type to simple
* codeql config added
* Dependabot config added
* Frogbot config added
* improve  authenticate method parameters ([#183](https://github.com/BeyondTrust/go-client-library-passwordsafe/issues/183))
* initial commit ([#2](https://github.com/BeyondTrust/go-client-library-passwordsafe/issues/2))
* launch please release app ([#140](https://github.com/BeyondTrust/go-client-library-passwordsafe/issues/140))
* put 30 seconds as default client time out ([#39](https://github.com/BeyondTrust/go-client-library-passwordsafe/issues/39))
* Ready to release
* Release please config added
* Release please yaml added
* remove verifyca from required list ([#86](https://github.com/BeyondTrust/go-client-library-passwordsafe/issues/86))
* return error when occurs from secrets flow ([#142](https://github.com/BeyondTrust/go-client-library-passwordsafe/issues/142))
* Support API Key Authentication ([#139](https://github.com/BeyondTrust/go-client-library-passwordsafe/issues/139))
* use a struct to group validate input function parameters ([#116](https://github.com/BeyondTrust/go-client-library-passwordsafe/issues/116))
* Workflow init ([#1](https://github.com/BeyondTrust/go-client-library-passwordsafe/issues/1))

#### Bug Fixes

* adding checks for PR workflow run ([#74](https://github.com/BeyondTrust/go-client-library-passwordsafe/issues/74))
* artifactory documentation updated ([#131](https://github.com/BeyondTrust/go-client-library-passwordsafe/issues/131))
* change library imports paths ([#71](https://github.com/BeyondTrust/go-client-library-passwordsafe/issues/71))
* change module name in .mod file ([#65](https://github.com/BeyondTrust/go-client-library-passwordsafe/issues/65))
* client credentials are not required, add apikey validation ([#154](https://github.com/BeyondTrust/go-client-library-passwordsafe/issues/154))
* code cognitive complexity in go library repo ([#204](https://github.com/BeyondTrust/go-client-library-passwordsafe/issues/204))
* ContactEmail default value for creating managed system by workgroup is invalid ([#250](https://github.com/BeyondTrust/go-client-library-passwordsafe/issues/250))
* file download ([#33](https://github.com/BeyondTrust/go-client-library-passwordsafe/issues/33))
* fix wrong spanish error message in validator ([#190](https://github.com/BeyondTrust/go-client-library-passwordsafe/issues/190))
* Fixing codeql behavior
* Fixing Go Linter ([#153](https://github.com/BeyondTrust/go-client-library-passwordsafe/issues/153))
* improve authenticate method call parameters in fuzzing test ([#184](https://github.com/BeyondTrust/go-client-library-passwordsafe/issues/184))
* improve README.md file and update dependencies ([#211](https://github.com/BeyondTrust/go-client-library-passwordsafe/issues/211))
* long paths not parsing correctly ([#50](https://github.com/BeyondTrust/go-client-library-passwordsafe/issues/50))
* managed system creation by asset has wrong default values ([#243](https://github.com/BeyondTrust/go-client-library-passwordsafe/issues/243))
* plugin crashed - with nonexistent API server ([#192](https://github.com/BeyondTrust/go-client-library-passwordsafe/issues/192))
* return error when secret was not found ([#145](https://github.com/BeyondTrust/go-client-library-passwordsafe/issues/145))
* security findings resolved and fixed ([#130](https://github.com/BeyondTrust/go-client-library-passwordsafe/issues/130))
* signout method ([#81](https://github.com/BeyondTrust/go-client-library-passwordsafe/issues/81))
* solve minnor issues and linting issues ([#30](https://github.com/BeyondTrust/go-client-library-passwordsafe/issues/30))

#### Miscellaneous Chores

* release 0.1.0 ([#10](https://github.com/BeyondTrust/go-client-library-passwordsafe/issues/10))
* release 0.23.0 ([#273](https://github.com/BeyondTrust/go-client-library-passwordsafe/issues/273))

### [0.22.1](https://github.com/BeyondTrust/go-client-library-passwordsafe/compare/v0.22.0...v0.22.1) / 2025-05-28

#### Bug Fixes

* ContactEmail default value for creating managed system by workgroup is invalid ([#250](https://github.com/BeyondTrust/go-client-library-passwordsafe/issues/250))

### [0.22.0](https://github.com/BeyondTrust/go-client-library-passwordsafe/compare/v0.21.1...v0.22.0) / 2025-05-23

#### Features

* add support for API version (3.0, 3.1) in create credential, text and file features ([#246](https://github.com/BeyondTrust/go-client-library-passwordsafe/issues/246))

### [0.21.1](https://github.com/BeyondTrust/go-client-library-passwordsafe/compare/v0.21.0...v0.21.1) / 2025-05-09

#### Bug Fixes

* managed system creation by asset has wrong default values ([#243](https://github.com/BeyondTrust/go-client-library-passwordsafe/issues/243))

### [0.21.0](https://github.com/BeyondTrust/go-client-library-passwordsafe/compare/v0.20.0...v0.21.0) / 2025-04-24

#### Features

* Add Functional Account datasource and get functional accounts list resource in terraform provider ([#234](https://github.com/BeyondTrust/go-client-library-passwordsafe/issues/234))

### [0.20.0](https://github.com/BeyondTrust/go-client-library-passwordsafe/compare/v0.19.0...v0.20.0) / 2025-04-09

#### Features

* add creating Managed System feature associated with Databases ([#228](https://github.com/BeyondTrust/go-client-library-passwordsafe/issues/228))

### [0.19.0](https://github.com/BeyondTrust/go-client-library-passwordsafe/compare/v0.18.0...v0.19.0) / 2025-04-03

#### Features

* add creating Managed System feature associated with Workgroups ([#223](https://github.com/BeyondTrust/go-client-library-passwordsafe/issues/223))

### [0.18.0](https://github.com/BeyondTrust/go-client-library-passwordsafe/compare/v0.17.0...v0.18.0) / 2025-03-26

#### Features

* add creating Managed System feature associated with Assets ([#209](https://github.com/BeyondTrust/go-client-library-passwordsafe/issues/209))

#### Bug Fixes

* code cognitive complexity in go library repo ([#204](https://github.com/BeyondTrust/go-client-library-passwordsafe/issues/204))
* improve README.md file and update dependencies ([#211](https://github.com/BeyondTrust/go-client-library-passwordsafe/issues/211))

### [0.17.0](https://github.com/BeyondTrust/go-client-library-passwordsafe/compare/v0.16.0...v0.17.0) / 2025-03-11

#### Features

* add creating Databases feature in terraform provider ([#201](https://github.com/BeyondTrust/go-client-library-passwordsafe/issues/201))

### [0.16.0](https://github.com/BeyondTrust/go-client-library-passwordsafe/compare/v0.15.0...v0.16.0) / 2025-02-27

#### Features

* add creating assets feature in terraform provider ([#199](https://github.com/BeyondTrust/go-client-library-passwordsafe/issues/199))

### [0.15.0](https://github.com/BeyondTrust/go-client-library-passwordsafe/compare/v0.14.3...v0.15.0) / 2025-02-24

#### Features

* add creating Workgroups feature in terraform provider ([#196](https://github.com/BeyondTrust/go-client-library-passwordsafe/issues/196))

### [0.14.3](https://github.com/BeyondTrust/go-client-library-passwordsafe/compare/v0.14.2...v0.14.3) / 2025-02-07

#### Bug Fixes

* plugin crashed - with nonexistent API server ([#192](https://github.com/BeyondTrust/go-client-library-passwordsafe/issues/192))

### [0.14.2](https://github.com/BeyondTrust/go-client-library-passwordsafe/compare/v0.14.1...v0.14.2) / 2025-02-03

#### Bug Fixes

* fix wrong spanish error message in validator ([#190](https://github.com/BeyondTrust/go-client-library-passwordsafe/issues/190))

### [0.14.1](https://github.com/BeyondTrust/go-client-library-passwordsafe/compare/v0.14.0...v0.14.1) / 2025-01-17

#### Bug Fixes

* improve authenticate method call parameters in fuzzing test ([#184](https://github.com/BeyondTrust/go-client-library-passwordsafe/issues/184))

### [0.14.0](https://github.com/BeyondTrust/go-client-library-passwordsafe/compare/v0.13.0...v0.14.0) / 2025-01-16

#### Features

* add api version parameter ([#180](https://github.com/BeyondTrust/go-client-library-passwordsafe/issues/180))
* improve  authenticate method parameters ([#183](https://github.com/BeyondTrust/go-client-library-passwordsafe/issues/183))

### [0.13.0](https://github.com/BeyondTrust/go-client-library-passwordsafe/compare/v0.12.0...v0.13.0) / 2024-12-11

#### Features

* add creating safes feature in terraform provider ([#175](https://github.com/BeyondTrust/go-client-library-passwordsafe/issues/175))
* add fuzzing tests ([#171](https://github.com/BeyondTrust/go-client-library-passwordsafe/issues/171))

### [0.12.0](https://github.com/BeyondTrust/go-client-library-passwordsafe/compare/v0.11.0...v0.12.0) / 2024-12-02

#### Features

* add logs in performance test ([#169](https://github.com/BeyondTrust/go-client-library-passwordsafe/issues/169))

### [0.11.0](https://github.com/BeyondTrust/go-client-library-passwordsafe/compare/v0.10.0...v0.11.0) / 2024-11-29

#### Features

* add creating folders feature in terraform provider ([#165](https://github.com/BeyondTrust/go-client-library-passwordsafe/issues/165))

### [0.10.0](https://github.com/BeyondTrust/go-client-library-passwordsafe/compare/v0.9.1...v0.10.0) / 2024-11-26

#### Features

* add writing secrets feature in terraform provider ([#161](https://github.com/BeyondTrust/go-client-library-passwordsafe/issues/161))

### [0.9.1](https://github.com/BeyondTrust/go-client-library-passwordsafe/compare/v0.9.0...v0.9.1) / 2024-11-08

#### Bug Fixes

* client credentials are not required, add apikey validation ([#154](https://github.com/BeyondTrust/go-client-library-passwordsafe/issues/154))

### [0.9.0](https://github.com/BeyondTrust/go-client-library-passwordsafe/compare/v0.8.1...v0.9.0) / 2024-11-08

#### Features

* add writing managed accounts feature in terraform provider ([#152](https://github.com/BeyondTrust/go-client-library-passwordsafe/issues/152))
* BIPS-18112 Enforce PR link to Jira ([#147](https://github.com/BeyondTrust/go-client-library-passwordsafe/issues/147))

#### Bug Fixes

* Fixing Go Linter ([#153](https://github.com/BeyondTrust/go-client-library-passwordsafe/issues/153))

### [0.8.1](https://github.com/BeyondTrust/go-client-library-passwordsafe/compare/v0.8.0...v0.8.1) / 2024-10-21

#### Bug Fixes

* return error when secret was not found ([#145](https://github.com/BeyondTrust/go-client-library-passwordsafe/issues/145))

### [0.8.0](https://github.com/BeyondTrust/go-client-library-passwordsafe/compare/v0.7.0...v0.8.0) / 2024-10-18

#### Features

* return error when occurs from secrets flow ([#142](https://github.com/BeyondTrust/go-client-library-passwordsafe/issues/142))

### [0.7.0](https://github.com/BeyondTrust/go-client-library-passwordsafe/compare/v0.6.0...v0.7.0) / 2024-10-17

#### Features

* launch please release app ([#140](https://github.com/BeyondTrust/go-client-library-passwordsafe/issues/140))
* Support API Key Authentication ([#139](https://github.com/BeyondTrust/go-client-library-passwordsafe/issues/139))

#### Bug Fixes

* artifactory documentation updated ([#131](https://github.com/BeyondTrust/go-client-library-passwordsafe/issues/131))
* security findings resolved and fixed ([#130](https://github.com/BeyondTrust/go-client-library-passwordsafe/issues/130))

### [0.6.0](https://github.com/BeyondTrust/go-client-library-passwordsafe/compare/v0.5.0...v0.6.0) / 2024-07-03

#### Features

* use a struct to group validate input function parameters ([#116](https://github.com/BeyondTrust/go-client-library-passwordsafe/issues/116))

### [0.5.0](https://github.com/BeyondTrust/go-client-library-passwordsafe/compare/v0.4.2...v0.5.0) / 2024-04-16

#### Features

* remove verifyca from required list ([#86](https://github.com/BeyondTrust/go-client-library-passwordsafe/issues/86))

### [0.4.1](https://github.com/BeyondTrust/go-client-library-passwordsafe/compare/v0.4.0...v0.4.1) / 2024-03-20

#### Bug Fixes

* change library imports paths ([#71](https://github.com/BeyondTrust/go-client-library-passwordsafe/issues/71))
* change module name in .mod file ([#65](https://github.com/BeyondTrust/go-client-library-passwordsafe/issues/65))

### [0.4.0](https://github.com/BeyondTrust/go-client-library-passwordsafe/compare/v0.3.0...v0.4.0) / 2024-03-08

#### Features

* add performance test ([#56](https://github.com/BeyondTrust/go-client-library-passwordsafe/issues/56))

### [0.3.0](https://github.com/BeyondTrust/go-client-library-passwordsafe/compare/v0.2.1...v0.3.0) / 2024-03-05

#### Features

* put 30 seconds as default client time out ([#39](https://github.com/BeyondTrust/go-client-library-passwordsafe/issues/39))

#### Bug Fixes

* file download ([#33](https://github.com/BeyondTrust/go-client-library-passwordsafe/issues/33))
* long paths not parsing correctly ([#50](https://github.com/BeyondTrust/go-client-library-passwordsafe/issues/50))

### [0.2.1](https://github.com/BeyondTrust/go-client-library-passwordsafe/compare/v0.2.0...v0.2.1) / 2024-02-26

#### Bug Fixes

* solve minor issues and linting issues ([#30](https://github.com/BeyondTrust/go-client-library-passwordsafe/issues/30))

### [0.2.0](https://github.com/BeyondTrust/go-client-library-passwordsafe/compare/v0.1.0...v0.2.0) / 2024-02-23

#### Features

* initial commit ([#2](https://github.com/BeyondTrust/go-client-library-passwordsafe/issues/2))

### 0.1.0 / 2024-02-22

#### Features

* Changing release type to simple
* codeql config added
* Dependabot config added
* Frogbot config added
* Release please config added
* Release please yaml added
* Workflow init ([#1](https://github.com/BeyondTrust/go-client-library-passwordsafe/issues/1))

#### Bug Fixes

* Fixing codeql behavior

#### Miscellaneous Chores

* release 0.1.0 ([#10](https://github.com/BeyondTrust/go-client-library-passwordsafe/issues/10))
