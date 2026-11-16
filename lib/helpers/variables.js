export const Scoped = {
    AbsoluteIterator: 0,
    SequentialIO: {},
    DDOS_Verse: {},
    pendingSignups: {},
    cacheTranformVideoTimer: {},
    FfmpegTranscodeTask: {},
    SequentialUid: {},
    Databases: {},
    expressInstances: {},
    /**
     * @type {{
     *    [projectName: string]: {
     *       mongoInstances: {
     *          [url: string]: import('mongodb').Db
     *       }
     *    }
     * }}
     */
    InstancesData: {},
    BlacklistedTokens: {},
    /**
     * @type {{ [key: string]: { callers: Map; destroy: () => void; }}}
     */
    AccumulatedDatabaseEmittions: {}
};