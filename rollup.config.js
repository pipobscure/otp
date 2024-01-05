import { nodeResolve } from '@rollup/plugin-node-resolve';
import commonJS from '@rollup/plugin-commonjs';

export default {
	input: 'build/otp.js',
	output: {
		name: 'otp',
		file: 'otp.js',
		format: 'umd',
	},
	plugins: [nodeResolve(), commonJS()],
};
