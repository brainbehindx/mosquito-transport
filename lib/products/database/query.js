import { Context } from "mingo/core";
import { Query } from "mingo/query";
import { resolve } from "mingo/util";
import { guardArray, GuardSignal, niceGuard, Validator } from "guard-object";
import { booleanIntersects } from '@turf/boolean-intersects';
import { booleanWithin } from '@turf/boolean-within';
import { booleanPointInPolygon } from "@turf/boolean-point-in-polygon";
import { nearestPointOnLine } from '@turf/nearest-point-on-line';
import { pointToPolygonDistance } from '@turf/point-to-polygon-distance';
import { circle } from '@turf/circle';
import { distance } from '@turf/distance';
import { point, polygon } from "@turf/helpers";
import { grab } from "poke-object";
import * as queryOperators from "mingo/operators/query";

const COORDINATE_GUARD = [
    GuardSignal.COORDINATE.LONGITUDE_INT,
    GuardSignal.COORDINATE.LATITUDE_INT
];

const EARTH_RADIUS = 6371.0088;

function planarDistanceSquared(a, b) {
    const dx = a[0] - b[0];
    const dy = a[1] - b[1];

    return dx * dx + dy * dy;
}

function pointWithinCenter(value, center, radius) {
    return (
        value.type === 'Point' &&
        planarDistanceSquared(
            value.coordinates,
            center
        ) <= radius * radius
    );
}

function getPointCoordinates(value) {
    if (
        value?.type === 'Point' &&
        Array.isArray(value.coordinates)
    ) {
        return value.coordinates;
    }

    // Legacy coordinate pair: [longitude, latitude]
    if (
        Array.isArray(value) &&
        Number.isFinite(value[0]) &&
        Number.isFinite(value[1])
    ) {
        return value;
    }

    // Legacy coordinate object: { x, y }
    if (
        value &&
        typeof value === 'object' &&
        !value.type &&
        Number.isFinite(value.x) &&
        Number.isFinite(value.y)
    ) {
        return [value.x, value.y];
    }

    return null;
}

const $geoWithin = (selector, args, options) => {
    const { $box, $geometry, $center, $centerSphere, $polygon } = args;

    return document => {
        const value = resolve(document, selector, options);
        if (!value) return false;

        try {
            if ($geometry) {
                if (
                    niceGuard({
                        $geometry: {
                            type: 'Polygon',
                            coordinates: guardArray(guardArray(COORDINATE_GUARD))
                        }
                    }, args) ||
                    niceGuard({
                        $geometry: {
                            type: 'MultiPolygon',
                            coordinates: guardArray(guardArray(guardArray(COORDINATE_GUARD)))
                        }
                    }, args)
                ) {
                    return value.type === 'Point'
                        ? booleanPointInPolygon(point(value.coordinates), $geometry)
                        : booleanWithin(value, $geometry);
                }
            } else if ($box) {
                if (niceGuard({ $box: Array(2).fill(COORDINATE_GUARD) }, args)) {
                    const coordinates = getPointCoordinates(value);

                    if (!coordinates) return false;

                    const [bottomLeft, topRight] = $box;

                    const [x, y] = coordinates;

                    return (
                        x >= bottomLeft[0] &&
                        x <= topRight[0] &&
                        y >= bottomLeft[1] &&
                        y <= topRight[1]
                    );
                }
            } else if ($center) {
                if (niceGuard({ $center: [COORDINATE_GUARD, GuardSignal.POSITIVE_NUMBER] }, args)) {
                    const [center, radius] = $center;
                    return pointWithinCenter(value, center, radius);
                }
            } else if ($centerSphere) {
                if (niceGuard({ $centerSphere: [COORDINATE_GUARD, GuardSignal.POSITIVE_NUMBER] }, args)) {
                    const [center, radius] = $centerSphere;
                    // Convert radians to km
                    return booleanWithin(value, circle(center, radius * EARTH_RADIUS, { units: 'kilometers' }));
                }
            } else if ($polygon) {
                if (niceGuard({ $polygon: guardArray(COORDINATE_GUARD) }, args)) {
                    const coordinates = getPointCoordinates(value);

                    if (!coordinates) return false;

                    const ring = [...$polygon];

                    if (ring.length < 3) {
                        throw new Error('A polygon requires at least 3 vertices');
                    }

                    const first = ring[0];
                    const last = ring[ring.length - 1];

                    if (
                        first[0] !== last[0] ||
                        first[1] !== last[1]
                    ) {
                        ring.push(first);
                    }

                    return booleanPointInPolygon(
                        point(coordinates),
                        polygon([ring])
                    );
                }
            }
        } catch (e) {
            return false;
        }
        throw new Error(`unknown operator: ${JSON.stringify(args, null, 2)}`);
    };
};

const $geoIntersects = (selector, args, options) => {
    const { $geometry } = args;

    return document => {
        const value = resolve(document, selector, options);
        if (!value) return false;

        if (
            !niceGuard({
                $geometry: {
                    type: 'Point',
                    coordinates: COORDINATE_GUARD
                }
            }, args) &&
            !niceGuard({
                $geometry: {
                    type: 'LineString',
                    coordinates: [COORDINATE_GUARD, COORDINATE_GUARD]
                }
            }, args) &&
            !niceGuard({
                $geometry: {
                    type: 'Polygon',
                    coordinates: guardArray(guardArray(COORDINATE_GUARD))
                }
            }, args) &&
            !niceGuard({
                $geometry: {
                    type: 'MultiPoint',
                    coordinates: guardArray(COORDINATE_GUARD)
                }
            }, args) &&
            !niceGuard({
                $geometry: {
                    type: 'MultiLineString',
                    coordinates: guardArray([COORDINATE_GUARD, COORDINATE_GUARD])
                }
            }, args) &&
            !niceGuard({
                $geometry: {
                    type: 'MultiPolygon',
                    coordinates: guardArray(guardArray(guardArray(COORDINATE_GUARD)))
                }
            }, args)
        ) throw new Error(`unknown operator: ${JSON.stringify(args, null, 2)}`);

        try {
            return booleanIntersects(value, $geometry);
        } catch (_) {
            return false;
        }
    };
};

function geometryDistanceMeters(origin, geometry) {
    const originPoint = point(origin.coordinates);

    switch (geometry.type) {
        case 'Point':
            return distance(originPoint, geometry, {
                units: 'meters'
            });

        case 'MultiPoint': {
            let minDistance = Infinity;

            for (const coordinates of geometry.coordinates) {
                const d = distance(originPoint, point(coordinates), {
                    units: 'meters'
                });

                if (d < minDistance) minDistance = d;
            }

            return minDistance;
        }

        case 'LineString':
        case 'MultiLineString': {
            const nearest = nearestPointOnLine(
                geometry,
                originPoint,
                { units: 'meters' }
            );

            return nearest.properties.pointDistance
                ?? nearest.properties.dist;
        }

        case 'Polygon':
        case 'MultiPolygon': {
            const d = pointToPolygonDistance(
                originPoint,
                geometry,
                {
                    units: 'meters',
                    method: 'geodesic'
                }
            );

            // Negative distance means the point is inside.
            return Math.max(0, d);
        }

        default:
            throw new Error(
                `Unsupported GeoJSON geometry: ${geometry.type}`
            );
    }
}

const $near = (selector, args, options) => {
    const { $geometry, $maxDistance, $minDistance } = args;

    if (
        !niceGuard({
            $geometry: {
                type: 'Point',
                coordinates: COORDINATE_GUARD
            },
            $minDistance: (t, p) =>
            (t === undefined ||
                (Validator.POSITIVE_NUMBER(t) &&
                    (p.$maxDistance === undefined || p.$maxDistance > t))),
            $maxDistance: (t, p) =>
            (t === undefined ||
                (Validator.POSITIVE_NUMBER(t) &&
                    (p.$minDistance === undefined || p.$minDistance < t)))
        }, args)
    ) throw new Error('Invalid geospatial arguments');

    return document => {
        const value = resolve(document, selector, options);
        if (!value) return false;

        try {
            const meters = geometryDistanceMeters($geometry, value);

            if ($minDistance !== undefined && meters < $minDistance) {
                return false;
            }

            if ($maxDistance !== undefined && meters > $maxDistance) {
                return false;
            }

            return true;
        } catch (error) {
            return false;
        }
    };
};

const $nearSphere = $near;

const $text = (_, args) => {
    const { $field, $search, $caseSensitive } = args;

    return document => {
        if (typeof $search !== 'string')
            throw new Error(`unknown operator: ${JSON.stringify(args, null, 2)}`);

        const searchValue = $caseSensitive ? $search : $search.toLowerCase();

        return (Array.isArray($field) ? $field : [$field]).some(v => {
            const f = typeof v === 'string' ? grab(document, v) : '';
            v = typeof f === 'string' ? f : '';
            if (!$caseSensitive)
                v = v.toLowerCase();

            return v.includes(searchValue);
        });
    }
}

const context =
    Context.init({
        query: { ...queryOperators }
    }).addQueryOps({
        $geoWithin,
        $geoIntersects,
        $near,
        $nearSphere,
        $text
    });

export function compileFilter(filter) {
    return new Query(toExtendedJSON(filter), { context });
}

export function testDocument(docs = [], query) {
    docs = toExtendedJSON(docs);

    if (!Array.isArray(docs)) docs = docs ? [docs] : [];

    try {
        if (!(query instanceof Query))
            query = compileFilter(query);

        return docs.some(v => query.test(v));
    } catch (error) {
        console.warn('testDocument err:', error);
        return false;
    }
}

export function isEqualId(a, b) {
    return testDocument([{ _id: a }], { _id: b });
}

export function toExtendedJSON(o) {
    if (Array.isArray(o)) return o.map(toExtendedJSON);

    if (Validator.OBJECT(o)) {
        return Object.fromEntries(
            Object.entries(o).map(([k, v]) => [k, toExtendedJSON(v)])
        );
    }

    if (typeof o?.toExtendedJSON === 'function') return o.toExtendedJSON();
    if (typeof o?.toJSON === 'function') return o?.toJSON();

    return o;
}