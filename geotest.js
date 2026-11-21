import { compileFilter } from "./lib/products/database/query.js";
import { MongoClient } from "mongodb";

const now = performance.now();

const documents = [
    {
        _id: 'point_inside',
        name: 'Point Inside',
        location: {
            type: 'Point',
            coordinates: [3.4, 6.5]
        }
    },
    {
        _id: 'point_boundary',
        name: 'Point On Boundary',
        location: {
            type: 'Point',
            coordinates: [3.5, 6.5]
        }
    },
    {
        _id: 'point_outside',
        name: 'Point Outside',
        location: {
            type: 'Point',
            coordinates: [4.0, 7.0]
        }
    },
    {
        _id: 'point_near',
        name: 'Point Nearby',
        location: {
            type: 'Point',
            coordinates: [3.41, 6.5]
        }
    },
    {
        _id: 'point_far',
        name: 'Point Far Away',
        location: {
            type: 'Point',
            coordinates: [3.8, 6.8]
        }
    },
    {
        _id: 'polygon_inside',
        name: 'Polygon Inside',
        location: {
            type: 'Polygon',
            coordinates: [[
                [3.35, 6.45],
                [3.45, 6.45],
                [3.45, 6.55],
                [3.35, 6.55],
                [3.35, 6.45]
            ]]
        }
    },
    {
        _id: 'polygon_intersect',
        name: 'Polygon Intersecting',
        location: {
            type: 'Polygon',
            coordinates: [[
                [3.45, 6.45],
                [3.55, 6.45],
                [3.55, 6.55],
                [3.45, 6.55],
                [3.45, 6.45]
            ]]
        }
    },
    {
        _id: 'polygon_outside',
        name: 'Polygon Outside',
        location: {
            type: 'Polygon',
            coordinates: [[
                [3.8, 6.8],
                [3.9, 6.8],
                [3.9, 6.9],
                [3.8, 6.9],
                [3.8, 6.8]
            ]]
        }
    }
];

const client = new MongoClient('mongodb://localhost:27017');

const geoCollection = () => client.db('STAGED_TESTING').collection('geofencing');


await geoCollection().insertMany(documents).catch(() => null);

const TestFootprint = [
    {
        location: {
            $geoWithin: {
                $geometry: {
                    type: 'Polygon',
                    coordinates: [[
                        [3.3, 6.4],
                        [3.5, 6.4],
                        [3.5, 6.6],
                        [3.3, 6.6],
                        [3.3, 6.4]
                    ]]
                }
            }
        }
    },

    {
        location: {
            $geoIntersects: {
                $geometry: {
                    type: 'Polygon',
                    coordinates: [[
                        [3.3, 6.4],
                        [3.5, 6.4],
                        [3.5, 6.6],
                        [3.3, 6.6],
                        [3.3, 6.4]
                    ]]
                }
            }
        }
    },

    {
        location: {
            $geoWithin: {
                $box: [
                    [3.3, 6.4],
                    [3.5, 6.6]
                ]
            }
        }
    },

    {
        location: {
            $geoWithin: {
                $polygon: [
                    [3.3, 6.4],
                    [3.5, 6.4],
                    [3.5, 6.6],
                    [3.3, 6.6]
                ]
            }
        }
    },

    {
        location: {
            $geoWithin: {
                $center: [
                    [3.4, 6.5],
                    0.02
                ]
            }
        }
    },

    {
        location: {
            $geoWithin: {
                $centerSphere: [
                    [3.4, 6.5],
                    0.001
                ]
            }
        }
    },

    {
        location: {
            $near: {
                $geometry: {
                    type: 'Point',
                    coordinates: [3.4, 6.5]
                },
                $maxDistance: 2000
            }
        }
    },

    {
        location: {
            $nearSphere: {
                $geometry: {
                    type: 'Point',
                    coordinates: [3.4, 6.5]
                },
                $maxDistance: 2000
            }
        }
    }
];


const cleanseResult = docs => docs.map(v => v._id).sort();

for (let index = 0; index < TestFootprint.length; index++) {
    const filter = TestFootprint[index];
    const res = await geoCollection().find(filter).toArray();
    const mongoRes = cleanseResult(res);
    const queryInstance = compileFilter(filter);
    const localRes = cleanseResult(documents.filter(v => queryInstance.test(v)));

    console.log('index:', index, ' mongo res:', mongoRes, ' local res:', localRes, ' equal:', JSON.stringify(mongoRes) === JSON.stringify(localRes), ' \n');
}

console.log('done:', performance.now() - now);

process.exit();