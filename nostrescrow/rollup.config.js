import resolve from '@rollup/plugin-node-resolve';
import commonjs from '@rollup/plugin-commonjs';
import typescript from '@rollup/plugin-typescript';
import json from '@rollup/plugin-json';

export default [
	// browser-friendly UMD build
	{
		input: 'src/index.ts',
		output: {
            interop: "compat",
            sourcemap: true,
			format: 'umd',
            dir: 'lib',
            name: "NostrEscrow",
		},
		plugins: [
			commonjs(),
			resolve({
                preferBuiltins: true,
                browser: true
            }),
			json(),
			typescript() 
		]
	},
];
