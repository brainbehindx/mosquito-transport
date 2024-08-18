export const Scoped = {
    pendingSignups: {},
    TokenSelfDestruction: {
        RefreshToken: {},
        AccessToken: {}
    },
    cacheTranformVideoTimer: {},
    SequentialUid: {},
    Databases: {},
    serverInstances: {},
    expressInstances: {},
    /**
     * @type {{
     *    [projectName: string]: {
     *       mongoInstances: {
     *          [url: string]: {
     *              defaultName: string,
     *              instance: import('mongodb').MongoClient
     *          }
     *       }
     *    }
     * }}
     */
    InstancesData: {}
}