# mosquitodb

MosquitoDB is a NoSQL database engine adapted with super fast, memory efficient, secured and fully queried features

## Installation

```sh
npm install mosquitodb
```

or using yarn

```sh
yarn add mosquitodb
```

## Usage

```js
import MosquitoDbServer from "mosquitodb";

// setup your server, easy as taking a candy from a baby

const heavenyaApp = new MosquitoDbServer({
  projectName: 'heavenya',
  port: 4534, // default to 4291
  signerKey: 'random_hash_key_for_signing_auth_requests', // must be 90 length
  databaseRules: ({ auth, collection, value, afterData, beforeData, operation, ...otherProps })=> new Promise((resolve, reject)=> {
    if (collection === 'user') {
        if(afterData && auth && auth.uid === value._id){
            resolve(true); // allow read/write
        }else reject();
    } // blah, blah, other algorithm
  }),
  storageRules: ({...props})=> new Promise(resolve=> {
    resolve(true) // handle read/write yourself here
  }),
});
```

your server is ready to be run on a node.js environment 🚀

## Contributing

See the [contributing guide](CONTRIBUTING.md) to learn how to contribute to the repository and the development workflow.

## License

MIT

---
