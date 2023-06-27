
export default class GlobalListener {
    constructor(initialValue) {
        this.listener = {};
        this.listenerMap = {};

        this.lastTriggerValue = initialValue || null;
        this.lastTriggerValueMap = {};

        this.lastListenerKey = 1;
    }

    startListener(callback, useLastTriggerValue = false) {
        const key = `${++this.lastListenerKey}`;
        let hasCancelled;

        if ((callback && typeof callback !== 'function') || typeof useLastTriggerValue !== 'boolean') throw 'Invalid param was parsed to startListener';
        this.listener[key] = callback;

        if (useLastTriggerValue)
            setTimeout(() => {
                if (!hasCancelled) callback?.(...(this.lastTriggerValue || []));
            }, 1);

        return () => {
            if (!hasCancelled) delete this.listener[key];
            hasCancelled = true;
        }
    }

    startKeyListener(key, callback, useLastTriggerValue = false) {
        if ((callback && typeof callback !== 'function') || typeof useLastTriggerValue !== 'boolean') throw 'Invalid param was parsed to startListener';

        if (!this.listenerMap[key]) this.listenerMap[key] = { ite: 0, triggers: {} };
        const node = `${++this.listenerMap[key].ite}`;
        let hasCancelled;

        this.listenerMap[key].triggers[node] = callback;

        if (useLastTriggerValue)
            setTimeout(() => {
                if (!hasCancelled) callback?.(...(this.lastTriggerValueMap[key] || []));
            }, 1);

        return () => {
            if (!hasCancelled) {
                delete this.listenerMap[key].triggers[node];
                if (!Object.keys(this.listenerMap[key].triggers).length) delete this.listenerMap[key];
            }
            hasCancelled = true;
        }
    }

    triggerListener() {
        const param = [...(arguments || [])];

        Object.keys(this.listener || {}).forEach(key => {
            this.listener[key]?.(...param);
        });
        this.lastTriggerValue = param;
    }

    triggerKeyListener() {
        const param = [...(arguments || [])],
            key = param[0],
            value = param.filter((_, i) => i);

        if (!key) throw 'expected a key in triggerKeyListener() first argument';

        Object.keys(this.listenerMap[key]?.triggers || {}).forEach(e => {
            this.listenerMap[key]?.triggers[e]?.(...value);
        });

        this.lastTriggerValueMap[key] = value;
    }
}