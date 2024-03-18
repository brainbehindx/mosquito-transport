# mosquito-transport

MosquitoTransport is a powerful tool that enables developers to persist and synchronize data between their MongoDB database and frontend applications. It offers a centralized and self-hosted solution for managing server infrastructure and data, along with robust authentication, real-time data updates, scalability, and cross-platform compatibility.

Under the hood, mosquito-transport uses Mongodb to store it data and [express](https://www.npmjs.com/package/express), [socket.io](https://www.npmjs.com/package/socket.io) for making request and [jwt](https://www.npmjs.com/package/jsonwebtoken) for signing authentication token, so make sure you have [mongodb](https://www.mongodb.com/docs/manual/installation/) installed before using this package.

## Key features of mosquito-transport include:

- ### Data Persistence and Synchronization 🔁: 
    - Seamlessly persist and synchronize data between MongoDB and frontend applications, ensuring consistency across all clients.

- ### Self-Hosted Server 💾: 
    - Host your own server infrastructure, giving you full control over data storage, access, and management.

- ### User Authentication and Authorization 🔐:
    - Easily implement user authentication and authorization using JWT (JSON Web Tokens), providing secure access control to your application's resources.

- ### End-to-End Encryption 🔗:
    - Optionally enforce end-to-end encryption by allowing only encrypted data to be transmitted between client and server, ensuring data privacy and security.

- ### Real-Time Data Updates 🚨:
    - Enable real-time updates to keep data synchronized across all clients in real-time, providing a seamless user experience.

- ### Scalability and Performance 🚛:
    - Benefit from auto-scaling and high performance, allowing your application to handle varying workloads with ease.

- ### Cross-Platform Compatibility 📱:
    - Compatible with React Native and web applications, allowing you to build cross-platform solutions with ease.


## Installation

```sh
npm install mosquito-transport
```

or using yarn

```sh
yarn add mosquito-transport
```

## Usage

```js
import MosquitoTransportServer from "mosquito-transport";
import { MongoClient } from 'mongodb';

// create a mongodb instance
const dbInstance = new MongoClient('mongodb://127.0.0.1:27017', {
    useNewUrlParser: true,
    useUnifiedTopology: true
});

dbInstance.connect().then(() => {
    console.log('connected to mongodb at');
}).catch(e => {
    console.error('failed to connected to mongodb at');
});

// setup your server
const serverApp = new MosquitoTransportServer({
  projectName: 'app_name',
  port: 4534, // defaults to 4291
  signerKey: 'random_90_hash_key_for_signing_jwt_tokens', // must be 90 length
  accessKey: 'this_is_my_private_password', // keep this private if you don't provide databaseRules or storageRules
  mongoInstances: {
      // this is where user info and tokens is stored
      admin: {
          instance: dbInstance,
          defaultName: 'ADMIN_DB_NAME'
      },
      // this will be the default db if no dbName was provided
      default: {
          instance: dbInstance,
          defaultName: 'DEFAULT_DB_NAME'
      }
  },
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

your server is now ready to be deploy on node.js! 🚀. Now install any mosquito-transport client sdk and start making requests to the server.

### SDKs And Hacks
- [react-native-mosquito-transport](https://github.com/deflexable/react-native-mosquito-transport) for react native apps
- [mosquito-transport-web](https://github.com/brainbehindx/mosquito-transport-js) for web platform
- [mongodb-hack-middleware](https://github.com/deflexable/mongodb-middleware-utils) for random query hack and fulltext search hack

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


<!-- ## Platform using MosquitoTransport in production
- [Heavenya - christian events](https://heavenya.com)
- [Inspire - christian audio](https://inspire.com)
- [ExamJoint - learn, study and prepare for exam](https://examjoint.com) -->

## Contributing

See the [contributing guide](CONTRIBUTING.md) to learn how to contribute to the repository and the development workflow.

## License

MIT

---