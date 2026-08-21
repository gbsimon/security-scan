// A maintenance script that really does call eval on user input.
// Careless, worth a look -- but there is no obfuscation here, nothing is
// packed, and this is not a build config or a git hook. MEDIUM, not HIGH.
const readline = require("readline");

function compute(expr) {
  return eval(expr);
}

module.exports = { compute };
