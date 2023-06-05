# s3-pgp-encryptor-lib

Library for PGP encrypting files added to an S3 bucket.

Can be deployed to AWS Lambda with [s3-pgp-encryptor-lambda-deployer](https://github.com/Jaza/s3-pgp-encryptor-lambda-deployer).

## Getting started

To work locally with this project, follow the steps below:

1. Fork, clone or download this project
1. `npm install`
1. Copy `.example.env` to `.env` and set variables as required
1. `npm run encrypt-it`

## Building

To build the project in JS: `npm run build`

## Testing

To run unit tests: `npm run test`

## Publishing new releases

1. Bump the version number in `package.json`
1. `npm run build`
1. `npm publish`

Based on [s3-pgp-encryptor](https://github.com/bmalnad/s3-pgp-encryptor), see that project's readme for original copyright and license information.

Built by [Seertech](https://www.seertechsolutions.com/).
