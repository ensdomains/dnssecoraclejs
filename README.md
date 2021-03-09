# dnssecoraclejs

A TypeScript/JavaScript library for generating proof data for the ENS DNSSEC Oracle.

## Installing

```
npm install '@ensdomains/dnssecoraclejs' --save
```

## Usage

```js
import { Oracle } from '@ensdomains/dnssecoraclejs'
const oracle = new Oracle(oracleAddress, provider)
// Refer to https://github.com/ensdomains/dnsprovejs for how to query result data
const { data, proof } = oracle.getProofData(result)
```

## Testing

```
  npm run test
```
