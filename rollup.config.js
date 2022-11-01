import resolve from '@rollup/plugin-node-resolve';
import { terser } from 'rollup-plugin-terser';
import pkg from './package.json';

const name = pkg.name
	.replace(/^\w/, m => m.toUpperCase())
	.replace(/-\w/g, m => m[1].toUpperCase());

export default {
	input: 'client/crypto-wraps.js',
	output: [
		{ file: pkg.module, 'format': 'es' }
	],
	plugins: [
		resolve(),
		terser({
			ecma: 2020,
			mangle: { toplevel: true },
			compress: {
			  module: true,
			  toplevel: true,
			  unsafe_arrows: true
			}
		})
	]
};
