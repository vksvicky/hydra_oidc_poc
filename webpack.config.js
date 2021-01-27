/*
 Copyright 2020, 2021 Jan Dittberner


 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at

     http://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.
 */

const path = require('path');
const CopyPlugin = require('copy-webpack-plugin');
const MiniCssExtractPlugin = require("mini-css-extract-plugin");
const TerserPlugin = require("terser-webpack-plugin");
const {WebpackManifestPlugin} = require("webpack-manifest-plugin");
const {CleanWebpackPlugin} = require("clean-webpack-plugin");

module.exports = {
    mode: process.env.NODE_ENV === 'production' ? 'production' : 'development',
    entry: {
        cacert: [
            path.resolve(__dirname, 'frontend_src/index.js'),
            path.resolve(__dirname, 'frontend_src/_custom.scss'),
        ]
    },
    plugins: [
        new CleanWebpackPlugin({cleanStaleWebpackAssets: false}),
        new WebpackManifestPlugin(),
        new MiniCssExtractPlugin({
            filename: "css/[name].bundle.css",
        }),
        new CopyPlugin({
            patterns: [
                {
                    from: "images/**",
                    context: path.resolve(__dirname, "frontend_src"),
                }
            ],
        }),
    ],
    output: {
        path: path.resolve(__dirname, 'static'),
        filename: 'js/[name].bundle.js',
    },
    devtool: 'source-map',
    optimization: {
        minimize: true,
        minimizer: [new TerserPlugin()],
    },
    module: {
        rules: [
            {
                test: /\.(svg|png|jpg|jpeg|gif)$/,
                type: "asset/resource",
            },
            {
                test: /\.scss$/,
                use: [{
                    loader: MiniCssExtractPlugin.loader,
                    options: {
                        publicPath: "/static/",
                    }
                }, {
                    loader: 'css-loader',
                    options: {
                        importLoaders: 1,
                        modules: {auto: true},
                    }
                }, {
                    loader: 'postcss-loader',
                    options: {
                        postcssOptions: {
                            plugins: [
                                [
                                    'precss',
                                    'autoprefixer',
                                ],
			    ],
                        },
                    },
                }, {
                    loader: 'sass-loader',
                }]
            }
        ],
    },
}
