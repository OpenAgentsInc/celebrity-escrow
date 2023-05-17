import resolve from '@rollup/plugin-node-resolve';
import commonjs from '@rollup/plugin-commonjs';
import typescript from '@rollup/plugin-typescript';

export default [
	// browser-friendly UMD build
	{
		input: 'src/index.ts',
		output: {
            sourcemap: true,
			format: 'umd',
            dir: 'lib',
            name: "NostrEscrow",
		},
		plugins: [
			resolve(),
			commonjs(),
			typescript() 
		]
	},
];
