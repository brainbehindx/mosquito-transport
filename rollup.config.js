import babel from '@rollup/plugin-babel';
import resolve from '@rollup/plugin-node-resolve';
import { terser } from 'rollup-plugin-terser';

export default {
    input: './lib/index.js',
    plugins: [
        resolve(),
        babel({
            babelHelpers: 'bundled',
            presets: [
                ['@babel/preset-env', { targets: { node: 'current' }, modules: false }],
            ],
        }),
        // terser(),
    ],
    output: [
        {
            dir: 'dist/esm',
            format: 'es',
            assetFileNames: '[name].[ext]'
        },
        {
            dir: 'dist/cjs',
            format: 'cjs',
            assetFileNames: '[name].[ext]'
        },
        // {
        //   file: 'dist/esm/index.min.js',
        //   format: 'es',
        // },
    ],
    external: ['mongodb', 'express', 'url', 'path', 'compression', 'socket.io','json-buffer', ''], // Add other external dependencies
};