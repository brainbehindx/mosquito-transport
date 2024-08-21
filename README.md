# mosquito-transport

MosquitoTransport is a powerful wrapper around mongodb and express that enables developers to persist and synchronize data between their MongoDB database and frontend applications. It offers a centralized and self-hosted solution for managing server infrastructure and data, along with robust authentication, real-time data updates, scalability, and cross-platform compatibility.

Under the hood, mosquito-transport uses Mongodb to store it data, along with [express](https://www.npmjs.com/package/express), [socket.io](https://www.npmjs.com/package/socket.io) for making request and [jwt](https://www.npmjs.com/package/jsonwebtoken) for signing authentication token, so make sure you have [mongodb](https://www.mongodb.com/docs/manual/installation/) installed before using this package.

## Key features of mosquito-transport include:

- Data Persistence and Synchronization 🔁:
  - Seamlessly persist and synchronize data between MongoDB and frontend applications, ensuring consistency across all clients.
- Self-Hosted Server 💾:
  - Host your own server infrastructure, giving you full control over data storage, access, and management.
- User Authentication and Authorization 🔐:
  - Easily implement user authentication and authorization using JWT (JSON Web Tokens), providing secure access control to your application's resources.
- End-to-End Encryption 🔗:
  - Optionally enforce end-to-end encryption by allowing only encrypted data to be transmitted between client and server, ensuring data privacy and security.
- Real-Time Data Updates 🚨:
  - Enable real-time updates to keep data synchronized across all clients in real-time, providing a seamless user experience.
- Scalability and Performance 🚛:
  - Benefit from auto-scaling and high performance, allowing your application to handle varying workloads with ease.
- Cross-Platform Compatibility 📱:
  - Compatible with React Native and web applications, allowing you to build cross-platform solutions with ease.
- Easy Data Backup and Restore 💿:
  - Effortlessly secure your data with seamless backup and restore functionality, ensuring quick and reliable recovery whenever needed

## Installation

```sh
npm install mosquito-transport mongodb --save
```

or using yarn

```sh
yarn add mosquito-transport mongodb
```

## Usage

```js
import MosquitoTransportServer from "mosquito-transport";
import { MongoClient } from "mongodb";

// create a mongodb instance
const dbInstance = new MongoClient("mongodb://127.0.0.1:27017");

dbInstance
  .connect()
  .then(() => {
    console.log("connected to mongodb");
  })
  .catch((e) => {
    console.error("failed to connected to mongodb");
  });

// setup your server
const serverApp = new MosquitoTransportServer({
  projectName: "app_name",
  port: 4534, // defaults to 4291
  signerKey: "random_90_hash_key_for_signing_jwt_tokens", // must be 90 length
  accessKey: "some_unique_string",
  externalAddress: "https://example.yourdomain.com",
  mongoInstances: {
    // this is where user info and tokens is stored
    admin: {
      instance: dbInstance,
      defaultName: "ADMIN_DB_NAME",
    },
    // this will be the default db if no dbName was provided
    default: {
      instance: dbInstance,
      defaultName: "DEFAULT_DB_NAME",
    },
  },
  databaseRules: ({
    auth,
    collection,
    value,
    afterData,
    beforeData,
    operation,
    ...otherProps
  }) =>
    new Promise((resolve, reject) => {
      // validate and authorize all incoming request to the database
      if (collection === "user") {
        if (afterData && auth && auth.uid === value._id) {
          resolve(); // allow read/write
        } else reject("You don`t own this data, stay away"); // reject read/write
      } else if (collection === "other_paths") {
        // blah, blah, other algorithm ...
      }
    }),
  storageRules: ({ ...props }) =>
    new Promise((resolve) => {
      // validate and authorize all uploads/downloads
      resolve(true); // handle read/write yourself here
    }),
  googleAuthConfig: {
    clientID: "your_google_authentication_clientID.apps.googleusercontent.com",
  },
  appleAuthConfig: {
    ...props,
  },
  ...otherProps,
});
```

your server is now ready to be deploy on node.js! 🚀. Now install any mosquito-transport client sdk and start making requests to the server.

### SDKs And Hacks

- [react-native-mosquito-transport](https://github.com/deflexable/react-native-mosquito-transport) for react native apps
- [mosquito-transport-web](https://github.com/brainbehindx/mosquito-transport-js) for web platform
- [mongodb-hack-middleware](https://github.com/deflexable/mongodb-middleware-utils) hacks for querying random document and fulltext search

## Additional Documentations

- [MosquitoTransportServer Constructor](#MosquitoServerConfig)
  - [projectName](#projectName)
  - [signerKey](#signerKey)
  - [port](#port)
  - [storageRules](#storageRules)
  - [databaseRules](#databaseRules)
  - [accessTokenInterval](#accessTokenInterval)
  - [refreshTokenExpiry](#refreshTokenExpiry)
  - [accessKey](#accessKey)
  - [mongoInstances](#mongoInstances)
  - [externalAddress](#externalAddress)
  - [hostname](#hostname)
  - [enableSequentialUid](#enableSequentialUid)
  - [mergeAuthAccount](#mergeAuthAccount)
  - [sneakSignupAuth](#sneakSignupAuth)
  - [onUserMounted](#onUserMounted)
  - [uidLength](#uidLength)
  - [enforceE2E](#enforceE2E)
  - [e2eKeyPair](#e2eKeyPair)
  - [logger](#logger)
  - [dumpsterPath](#dumpsterPath)
  - [preMiddlewares](#preMiddlewares)
  - [transformMediaRoute](#transformMediaRoute)
  - [transformMediaCleanupTimeout](#transformMediaCleanupTimeout)
  <!-- - [googleAuthConfig](#googleAuthConfig)
  - [appleAuthConfig](#appleAuthConfig)
  - [facebookAuthConfig](#facebookAuthConfig)
  - [githubAuthConfig](#githubAuthConfig)
  - [twitterAuthConfig](#twitterAuthConfig)
  - [fallbackAuthConfig](#fallbackAuthConfig) -->
  - [staticContentProps](#staticContentProps)
  - [staticContentMaxAge](#staticContentMaxAge)
  - [staticContentCacheControl](#staticContentCacheControl)
  - [corsOrigin](#corsOrigin)
  - [maxRequestBufferSize](#maxRequestBufferSize)
  - [maxUploadBufferSize](#maxUploadBufferSize)
- [MosquitoTransportServer Getters](#MosquitoTransportServer-Getters)
  - [storagePath](#storagePath)
  - [sampleE2E](#sampleE2E)
  - [express](#express)
- [MosquitoTransportServer Methods](#MosquitoTransportServer-Methods)
  - [getDatabase](#getDatabase)
  - [listenDatabase](#listenDatabase)
  - [listenStorage](#listenStorage)
  - [listenHttpsRequest](#listenHttpsRequest)
  - [listenNewUser](#listenNewUser)
  - [listenDeletedUser](#listenDeletedUser)
  - [verifyToken](#verifyToken)
  - [validateToken](#validateToken)
  - [invalidateToken](#invalidateToken)
  - [getUserData](#getUserData)
  - [updateUserProfile](#updateUserProfile)
  - [updateUserMetadata](#updateUserMetadata)
  - [updateUserClaims](#updateUserClaims)
  - [updateUserEmailAddress](#updateUserEmailAddress)
  - [updateUserPassword](#updateUserPassword)
  - [updateUserEmailVerify](#updateUserEmailVerify)
  - [signOutUser](#signOutUser)
  - [disableUser](#disableUser)
  - [uploadBuffer](#uploadBuffer)
  - [deleteFile](#deleteFile)
  - [deleteFolder](#deleteFolder)
  - [inspectDocDisconnectionTask](#inspectDocDisconnectionTask)
  - [linkToFile](#linkToFile)
  - [extractBackup](#extractBackup)
- [Extracting Backup](#Extracting-Backup)
  - [CLI backup extraction](#CLI-backup-extraction)
  - [Advance backup extraction](#Advance-backup-extraction)
- [Installing Backup](#Installing-Backup)
  - [CLI backup installation](#CLI-backup-installation)
  - [Advance backup installation](#Advance-backup-installation)
- [Authentication Setup](#authentication-setup)
  - [Merge Auth Account](#google-auth-setup)
  - [Google Auth Setup](#google-auth-setup)
  - [Apple Auth Setup](#apple-auth-setup)
  - [Facebook Auth Setup](#facebook-auth-setup)
  - [Twitter Auth Setup](#twitter-auth-setup)
  - [Github Auth Setup](#google-auth-setup)
  - [Fallback Auth Setup](#fallback-auth-setup)
  - [Google Auth Setup](#google-auth-setup)

## MosquitoServerConfig

### projectName

the name for your mosquito-transport instance. this is required and used internally by both the backend and frontend client.

### signerKey

a 90 character string which is used in signing jwt access and refresh token.

### port

the port number you want mosquito-transport instance to be running on

### storageRules

a function used for securing all file operations (`uploadFile`, `downloadFile`, `deleteFile`, `deleteFolder`) made by the frontend client.

<!-- TODO: show examples -->

### databaseRules

a function used for securing all mongodb read and write operations made by the frontend client.

<!-- show examples -->

### accessTokenInterval

numbers of milliseconds until generated access token expires. Defaults to `1 hour` (3600000).

### refreshTokenExpiry

numbers of milliseconds until generated refresh token expires. Defaults to `1 month` (2419200000).

### accessKey

a random string used by the frontend client for accessing internal resources.

### mongoInstances

an object that maps names to your mongodb instance. if no `dbRef` were provided, the `default` mongodb instance will be used.

```js
import MosquitoTransportServer from "mosquito-transport";
import { MongoClient } from "mongodb";

// create a mongodb instance
const dbInstance = new MongoClient("mongodb://127.0.0.1:27017");

dbInstance.connect();

const remoteInstance = new MongoClient("mongodb://other-searver.com");

remoteInstance.connect();

const serverApp = new MosquitoTransportServer({
  ...otherProps,
  mongoInstances: {
    // frontend client are prohitted from accessing this instance
    admin: {
      instance: dbInstance,
      defaultName: "ADMIN_DB_NAME",
    },
    // this will be the default db if no dbRef was provided by the frontend client
    default: {
      instance: dbInstance,
      defaultName: "DEFAULT_DB_NAME",
    },
    // additional instance
    remoteBackup: {
      instance: remoteInstance,
      defaultName: "WEB_BACKUP",
    },
  },
});

// then you can access this via frontend client

const webInstance = new MosquitoTransport({
  projectUrl: "http://localhost:4534/app_name",
  accessKey: "some_unique_string",
  ...options,
});

webInstance
  .getDatabase(
    // if this is undefined, the server will use `defaultName` as the default name
    "database_name",
    // the name of the mongoInstances map
    "remoteBackup"
  )
  .collection("transactions")
  .findOne({ date: { $gt: 1719291129937 } })
  .get();

// or access the default db

webInstance.getDatabase().collection("testing");
```

### externalAddress

this should be a valid http or https link. it is used internally while signing jwt and for prefixing storage `downloadUrl` when uploading a file by frontend client.

### hostname

if no `externalAddress` was provided, `externalAddress` will be a construct as follows:

```js
`http://${hostname || "localhost"}:${port}`;
```

### enableSequentialUid

true if you want new users to be assign a sequential `uid` like 0, 1, 2, 3, 4, 5, ...,

### mergeAuthAccount

true if you want to threat the same email address from different auth provider as a single user.

### sneakSignupAuth

a function use in preventing signup and adding metadata before signup

```js
import MosquitoTransportServer, { AUTH_PROVIDER_ID } from "mosquito-transport";

const blacklisted_country = ["RU", "AF", "NG"];

const serverApp = new MosquitoTransportServer({
  ...otherProps,
  sneakSignupAuth: ({ request, email, name, password, method }) => {
    const geo = lookupIpAddress(request.ip);
    if (!geo) throw "Failed to lookup request location";

    if (blacklisted_country.includes(geo.country))
      throw "This platform is not yet available in your location";

    if (method === AUTH_PROVIDER_ID.PASSWORD && password.length < 5)
      throw "password is too short";

    const uid = randomString(11),
      lang = getCountryLang(geo?.country || "US");

    return {
      metadata: {
        country: geo.country,
        city: geo.city,
        location: geo.ll,
        tz: geo?.timezone,
        ip: request.ip,
        locale: "en",
      },
      uid,
    };
  },
});
```

### onUserMounted

a function that is called when a user's mosquito client sdk is authenticated and online

```js
import MosquitoTransportServer from "mosquito-transport";

const serverApp = new MosquitoTransportServer({
  ...otherProps,
  onUserMounted: ({ user, headers }) => {
    // update the user online status
    serverApp.collection("users").updateOne(
      { _id: user.uid },
      {
        status: "online",
        onlineOn: Date.now(),
      }
    );

    return () => {
      // update the user offline status
      serverApp.collection("users").updateOne(
        { _id: user.uid },
        {
          status: "offline",
          offlineOn: Date.now(),
        }
      );
    };
  },
});
```

### uidLength

the length of generated user uid. default to `30`.

### enforceE2E

true if you want to enforce end-to-end encryption for all request made by the server

### e2eKeyPair

an array of string, `[public key, private key]`. You can get a sample as follows:

```js
import MosquitoTransportServer from "mosquito-transport";

const serverApp = new MosquitoTransportServer({ ...options });

console.log("pair key", serverApp.sampleE2E);
```

### dumpsterPath

path to where mosquito-transport stores it files. Defaults to the current working directory.

### preMiddlewares

this will be the first middleware that will be executed for all incoming http request to this mosquito-transport instance.

You may intercept this middleware to manage and prevent ddos attack and handle some custom route such as `favicon.ico`

```js
import MosquitoTransportServer from "mosquito-transport";

const serverApp = new MosquitoTransportServer({
  ...otherProps,
  preMiddlewares: (req, res, next) => {
    // do some enforcement checking here
    next();
  },
});
```

### transformMediaRoute

this option helps you to transform image and video files on the fly without having to write boilerplate code for this.
All you have to do is set `transformMediaRoute` to `*` as follows:

```js
import MosquitoTransportServer from "mosquito-transport";

const serverApp = new MosquitoTransportServer({
  ...otherProps,
  transformMediaRoute: "*",
});
```

now you can automatically transform images and video by appending some query parameter to the url of the image or video you're accessing.

#### Image Parameters

the following list the parameters available for image media

- `width` or `w`: a number that sets the width of the image
- `height` or `h`: a number that sets the height of the image
- `top` or `t`: a number that sets the top position of the image
- `left` or `l`: a number that sets the left position of the image
- `grayscale`or `gray`: set this to `1` or `true` if you want the image in grayscale
- `blur` or `b`: either set this to `true` to blur the image or a value between 0.3 and 1000 representing the sigma of the Gaussian mask, where sigma = 1 + radius / 2.
- `flip`: set to `true` or `1` to flip the image about the vertical Y axis. The use of flip implies the removal of the EXIF Orientation tag, if any.
- `flop`: set to `true` or `1` to flop the image about the horizontal X axis. The use of flop implies the removal of the EXIF Orientation tag, if any.
- `format` or `o`: this set the output format of the image, can be any of `avif`, `dz`, `fits`, `gif`, `heif`, `input`, `jpeg`, `jpg`, `jp2`, `jxl`, `magick`, `openslide`, `pdf`, `png`, `ppm`, `raw`, `svg`, `tiff`, `tif`, `v` or `webp`
- `quality` or `q`: set the quality of the image from a scale of 0 - 1.
- `lossless` or `loss`: set to `1` or `true` to use lossless compression mode

**_Example_**
the following transform the image at `http://localhost:5622/storage/users/richard/photo.png`:

```js
// resize the image to 70 width and scale the height respectively
`http://localhost:5622/storage/users/richard/photo.png?w=70` // apply grayscale to the image and set the quality to 0.3
`http://localhost:5622/storage/users/richard/photo.png?grayscale=true&q=0.3`;
```

#### Video Parameters

the following list the parameters available for video media

- `width` or `w`: a number that sets the width of the video.
- `height` or `h`: a number that sets the height of the video.
- `top` or `t`: a number that sets the top position of the video.
- `left` or `l`: a number that sets the left position of the video.
- `mute`: set to `1` or `true` to mute the video.
- `vbr`: set the bitrate of the video. Equivalent to `-v:a` command of ffmpeg.
- `abr`: set the bitrate of the audio. Equivalent to `-b:a` command of ffmpeg.
- `fps`: an integer to set the frame per seconds of the video. This parameter plays a significant role in reducing the output size and processing time of the video. Equivalent to `-r` command of ffmpeg.
- `grayscale`or `gray`: set this to `1` or `true` if you want the video in grayscale
- `flip`: set to `true` or `1` to flip the video about the vertical Y axis.
- `flop`: set to `true` or `1` to flop the video about the horizontal X axis.
- `quality` or `q`: set the quality of the video from a scale of 0 - 1.
- `lossless` or `loss`: set to `1` or `true` to use lossless compression mode
- `preset`: set the `-preset` of ffmpeg. Defaults to medium.
- `format` or `o`: this set the output format of the image, can be any of `avif`, `dz`, `fits`, `gif`, `heif`, `input`, `jpeg`, `jpg`, `jp2`, `jxl`, `magick`, `openslide`, `pdf`, `png`, `ppm`, `raw`, `svg`, `tiff`, `tif`, `v` or `webp`

**_Example_**
the following transform the video at `http://localhost:5622/storage/video/lil-yatchy/range-rover-sport-truck.mp4`:

```js
// resize the video to 200 height and scale the width respectively
`http://localhost:5622/storage/video/lil-yatchy/range-rover-sport-truck.mp4?height=200` // apply grayscale to the video, set the quality to 0.7 and set the fps to 30
`http://localhost:5622/storage/video/lil-yatchy/range-rover-sport-truck.mp4?grayscale=true&q=0.7&fps=30`;
```

**_Additional Dependency_**
Internally mosquito-transport uses `sharp` to transform images and `ffmpeg` to transform video, so make sure these library are installed before setting `transformMediaRoute: '*'`

```sh
yarn add sharp
```

### transformMediaCleanupTimeout

This is the numbers of milliseconds to cache the transformed video media file before it is deleted. This is basically to avoid the overhead processing time next time the frontend client tries to access it. Defaults to 7 hours.

# logger

can either be a string or array containing any of the following:

- `all`: log all requests
- `auth`: log authentication requests
- `database`: log database requests
- `storage`: log storage requests
- `external-requests`: log api requests
- `served-content`: log serve content requests
- `database-snapshot`: log database snapshot events

### staticContentProps

Static Content Props for storage file response. See [SendFileOptions](https://github.com/expressjs/expressjs/express-serve-static-core/index.d.ts)

### staticContentMaxAge

Provide a max-age in milliseconds for http caching. This will only be applied to storage file response.

### staticContentCacheControl

Enable or disable setting Cache-Control response header. This will only be applied to storage file response.

### corsOrigin

set cors origin for all outgoing request

### maxRequestBufferSize

the maximum size in bytes of each request payload. Default to 100MB

### maxUploadBufferSize

the maximum size in byte of each uploading request payload. Default to 10GB

## MosquitoTransportServer Getters

### storagePath

get the directory where storage files are saved

### sampleE2E

quickly get an end-to-end encryption [pair key](#[e2eKeyPair]) for your server

### express

get the internal express instance use

## MosquitoTransportServer Methods

### getDatabase

returns the db instance of mongodb.

```js
serverApp
  .getDatabase(
    // if this is undefined, the server will use `defaultName` as the default name
    "database_name",
    // the name of the mongoInstances map
    "remoteBackup"
  )
  .collection("transactions")
  .findOne({ date: { $gt: 1719291129937 } })
  .get();

// or access the default db

serverApp.getDatabase().collection("testing");
```

### listenDatabase

listen to insert, update and delete events from mongodb

```js
serverApp.listenDatabase("transactions", async (snapshot) => {
  console.log("transaction snapshot", snapshot);
});
```

### listenStorage

listen to storage event. these event are typically made by the frontend client.

```js
serverApp.listenStorage(async (event) => {
  console.log("storage event", event);
});
```

### listenHttpsRequest

listen to incoming request

```js
// only allow authenticated user to access this endpoint
serverApp.listenHttpsRequest(
  "check_user",
  async (req, res, user) => {
    // user will always be present
    res.status(200).send({ uid: user.uid });
  },
  {
    enforceVerifiedUser: true,
    enforceUser: true,
  }
);

// optionally allow un-authenticated user
serverApp.listenHttpsRequest(
  "server_time",
  async (req, res, user) => {
    // user may be present
    if (user) {
      res.status(200).send({ uid: user.uid });
    } else {
      res.status(403).send({ error: "No user provided" });
    }
  },
  {
    validateUser: true,
  }
);

// disable end-to-end encrytion for this endpoint and user authentication
serverApp.listenHttpsRequest(
  "server_time",
  async (req, res) => {
    res.status(200).send({ currentData: Date.now() });
  },
  {
    rawEntry: true,
  }
);
```

### listenNewUser

listen to new user

```js
serverApp.listenNewUser(async (user) => {
  console.log("new signup", user);
});
```

### listenDeletedUser

listen to deletedUser

```js
serverApp.listenDeletedUser((uid) => {
  console.log("deleted user", uid);
});
```

### parseToken

parse jwt token

### verifyToken

verify token to check if it was trully created using signerKey without checking against the expiry or local token reference

### validateToken

verify token to check if it was trully created using signerKey and checking against the expiry and local token reference

### invalidateToken

remove local reference of a token

### getUserData

get the user data belonging to a user

### updateUserProfile

update the profile data of a user

### updateUserMetadata

update user metadata

### updateUserClaims

update the custom claim of a user

### updateUserEmailAddress

update the email address of a user

### updateUserPassword

update the user password of a user

### updateUserEmailVerify

update the verify status of a user

### signOutUser

purge all tokens references for a user and sign-out the user immediately

### disableUser

disable a user

### uploadBuffer

upload a file to the storage directory

### deleteFile

delete file in the storage directory

### deleteFolder

delete folder in the storage directory

### linkToFile

convert a link to local file path.

### extractBackup

extract storage and database backup of the `MosquitoTransport` instance

### installBackup

install backup content from a source to their respective destination

```js
serverApp.linkToFile("http://localhost:5622/storage/users/richard/photo.png");
```

<!-- ## Platform using MosquitoTransport in production
- [Heavenya - christian events](https://heavenya.com)
- [Inspire - christian audio](https://inspire.com)
- [ExamJoint - learn, study and prepare for exam](https://examjoint.com) -->

## Extracting Backup

### CLI backup extraction

```sh
npx extract_mosquito_backup password=your_custom_password storage=../junk dest=./backup.bin dbName=my_admin_db/my_main_db/other_db
```

- `dest` is the destination to write the backup to, can be a file path or an http/https line. Defaults to `mosquito_backup.bin`.
- `dbName` should contain list of databases to extracts seperated with forward slash or "$" to extract all databases. backup is performed on "mongodb://localhost:27017".
- `password` is use for encrypting the backup data.
- `storage` is the directory to storage file.

Executing only `npx extract_mosquito_backup` will use "mosquito.config.js" file in the current working directory.
If the config file is not found, then command `npx extract_mosquito_backup dbName=$` will executed instead.

### Advance backup extraction

You can provide a custom configuration file for extracting backup like:

```sh
npx extract_mosquito_backup ./path/to/custom_backup_config.js
```

You are expected to export `extract` in your config file.
an example on how the content of the file should look like is shown below:

```js
export const extract = {
  password: "your_custom_password",
  storage: "./path/to/your/storage",
  dest: "https://api.mega.io/upload/backup/my_server", // can be a link or filepath
  destHeaders: {
    // only provide if "dest" is an http(s) link
    access_key: "backup_server_password",
  },
  database: {
    "mongodb://example.com:27017": {
      // <--- database url
      my_admin_db: "*", // <--- "*" to include all collection
      my_main_db: ["my_custom_collection", ...more],
    },
  },
  onMongodbOption: (dbUrl) => {
    // you can also return a `MongoClient` instance
    return {
      auth: {
        username: "my_mongodb_username",
        password: "my_mongodb_password",
      },
      ...otherProps,
    };
  },
};
```

## Installing Backup

### CLI backup installation

```sh
npx install_mosquito_backup password=your_custom_password storage=../junk source=./backup.bin
```

- `password` is use for encrypting the backup data
- `storage` is the directory to storage file
- `source` is the path to the backup, can be a file path or http/https link. Defaults to `mosquito_backup.bin`.

Executing only `npx install_mosquito_backup` will use "mosquito.config.js" file in the current working directory

### Advance backup installation

You can provide a custom configuration file for extracting backup like:

```sh
npx install_mosquito_backup ./path/to/custom_backup_config.js
```

You are expected to export `install` in your config file.
an example on how the content of the file should look like is shown below:

```js
export const install = {
  password: "your_backup_password",
  storage: "./path/to/your/storage",
  source: "https://api.mega.io/retrieve/backup/my_server", // can be a link or filepath
  sourceHeader: {
    // only provide if "source" is an http(s) link
    access_key: "backup_server_password",
  },
  onMongodbOption: (dbUrl) => {
    // you can also return a `MongoClient` instance
    return {
      url: "mongodb://...your_address_here", // <--- provide this to remap dbUrl to url
      auth: {
        username: "my_mongodb_username",
        password: "my_mongodb_password",
      },
      ...otherProps,
    };
  },
};
```

## Contributing

See the [contributing guide](CONTRIBUTING.md) to learn how to contribute to the repository and the development workflow.

## License

MIT

---
