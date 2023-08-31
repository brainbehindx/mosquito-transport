# mosquitodb

Mosquitodb transform your mongodb into a BaaS making data sychronization between client and server persistable and consistent. Mosquitodb is built together with [authentication](#authentication), [storage-rules](#storage-rules) and [database-rules](#database-rules) making your application more centralize and secure.

Under the hood, mosquitodb uses Mongodb to store it data and [express](https://www.npmjs.com/package/express), [socket.io](https://www.npmjs.com/package/socket.io) for making request, so make sure you have [mongodb](https://www.mongodb.com/docs/manual/installation/) installed before using this package.

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
  signerKey: 'random_90_hash_key_for_signing_jwt_tokens', // must be 90 length
  accessKey: 'this_is_my_private_password', // keep this private if you don't provide databaseRules or storageRules
  databaseRules: ({ auth, collection, value, afterData, beforeData, operation, ...otherProps })=> new Promise((resolve, reject)=> {
    // validate and authorize all incoming request to the database
    if (collection === 'user') {
        if (afterData && auth && auth.uid === value._id) {
            resolve(); // allow read/write
        } else reject('You don`t own this data, stay away'); // reject read/write
    } else if (collection === 'other_paths') {
      // blah, blah, other algorithm ...
    }
  }),
  storageRules: ({...props})=> new Promise(resolve=> {
    // validate and authorize all uploads/downloads
    resolve(true) // handle read/write yourself here
  }),
  googleAuthConfig: {
    clientID: 'your_google_authentication_clientID.apps.googleusercontent.com'
  },
  appleAuthConfig: {
    ...props
  },
  ...otherProps
});
```

your server is ready to be deploy on a node.js environment! 🚀. Now install any mosquitodb client sdk and start making requests to the server.

### SDKs
- [react-native-mosquitodb](https://github.com/deflexable/react-native-mosquitodb) for react native apps
- [mosquitodb-web](https://github.com/deflexable/mosquitodb-web) for web platform

## Additional Documentations
- [Logging Level](#logging-levels)
- [Database Rules](#database-rules)
- [Storage Rules](#storage-rules)
- [Authentication](#authentication)
   - [Merge Auth Account](#google-auth-setup)
   - [Google Auth Setup](#google-auth-setup)
   - [Apple Auth Setup](#apple-auth-setup)
   - [Facebook Auth Setup](#facebook-auth-setup)
   - [Twitter Auth Setup](#twitter-auth-setup)
   - [Github Auth Setup](#google-auth-setup)
   - [Fallback Auth Setup](#fallback-auth-setup)
   - [Google Auth Setup](#google-auth-setup)


<!-- ## Platform using Mosquitodb in production
- [Heavenya - christian events](https://heavenya.com)
- [Inspire - christian audio](https://inspire.com)
- [ExamJoint - learn, study and prepare for exam](https://examjoint.com) -->

## Contributing

See the [contributing guide](CONTRIBUTING.md) to learn how to contribute to the repository and the development workflow.

## License

MIT

---
