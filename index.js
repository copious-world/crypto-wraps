const crypto_wraps = require('./lib/crypto-wraps')

module.exports = crypto_wraps






const {browser_code} = require('roll-right')
module.exports.browser_code = () => { return browser_code(__dirname) }
