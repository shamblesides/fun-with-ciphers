var ciphers = (function() {
  function caesar(str, rot) {
    if(rot === '' || isNaN(+rot)) throw new Error('"Shift" must be a number.');
    //get rot to a be 0-25
    rot = rot%26;
    if(rot<=0) rot += 26;
    //replace lowercase, then caps
    var lz = 'z'.charCodeAt(0);
    var uZ = 'Z'.charCodeAt(0);
    return str.replace(/[a-z]/g, function(x) {
      var i = x.charCodeAt(0);
      return String.fromCharCode(i+rot - (i > lz-rot? 26:0));
    }).replace(/[A-Z]/g, function(x) {
      var i = x.charCodeAt(0);
      return String.fromCharCode(i+rot - (i > uZ-rot? 26:0));
    });
  }
  function toMorse(str) {
    var alphabet = {
      'a': '.-',    'b': '-...',  'c': '-.-.', 'd': '-..',
      'e': '.',     'f': '..-.',  'g': '--.',  'h': '....',
      'i': '..',    'j': '.---',  'k': '-.-',  'l': '.-..',
      'm': '--',    'n': '-.',    'o': '---',  'p': '.--.',
      'q': '--.-',  'r': '.-.',   's': '...',  't': '-',
      'u': '..-',   'v': '...-',  'w': '.--',  'x': '-..-',
      'y': '-.--',  'z': '--..',
      '1': '.----', '2': '..---', '3': '...--', '4': '....-', 
      '5': '.....', '6': '-....', '7': '--...', '8': '---..', 
      '9': '----.', '0': '-----',
      '.': '.-.-.-', ',': '--..--', '?': '..--..', '/': '-..-.',
      '@': '.--.-.', ':': '---...', "'": '.----.', '-': '-....-',
      '"': '.-..-.', '=': '-...-',
      '(': '-.--.-', ')': '-.--.-', '[': '-.--.-', ']': '-.--.-',
      '{': '-.--.-', '}': '-.--.-',
      ' ': '/',      '\n': '.-.-'
      
    }
    return str.split('').map(function(x){
      var thing = alphabet[x.toLowerCase()];
      if(thing === undefined) throw new Error('Unknown letter: ' + x);
      return thing;
    }).join(' ').replace(/ +/g, ' ');
  }
  function fromMorse(str) {
    var morse = {
      '.-': 'a',      '-...': 'b',    '-.-.': 'c',  '-..': 'd',
      '.':  'e',      '..-.': 'f',    '--.': 'g',   '....': 'h',
      '..': 'i',      '.---': 'j',    '-.-': 'k',   '.-..': 'l',
      '--': 'm',      '-.': 'n',      '---': 'o',   '.--.': 'p',
      '--.-': 'q',    '.-.': 'r',     '...': 's',   '-': 't',
      '..-': 'u',     '...-': 'v',    '.--': 'w',   '-..-': 'x',
      '-.--': 'y',    '--..': 'z',
      '.----': '1',   '..---': '2',   '...--': '3', '....-': '4',
      '.....': '5',   '-....': '6',   '--...': '7', '---..': '8',
      '----.': '9',   '-----': '0',
      '.-.-.-': '.',  '--..--': ',',  '..--..': '?', '-..-.': '/',
      '.--.-.': '@',  '---...': ':',  '.----.': "'",
      '-....-': '-',  '.-..-.': '"',  '-...-': '=',
      '-.--.-': '(',
      '/': ' ',       '.-.-': '\n'
    };
    return str.split(/ +/g).map(function(x) {
      if(!morse[x]) throw new Error('Unknown code: ' + x);
      return morse[x];
    }).join('');
  }
  return [
    {
      group: 'Classical Ciphers',
      desc: "<p><b>Classical ciphers</b> found their use centuries or even millenia ago. These simple ciphers primarily encrypt messages by operating on the individual letters of the message, either by changing their order, or by substituting each character. Each cipher goes about this in a different way.</p>"
      +"<p>Although these ciphers may have been useful historically, modern cryptanalysis renders these ciphers completely ineffective against knowledgeable attackers.</p>",
      list: [
        { name: 'Reverse', encode: esrever.reverse },
        { name: 'ROT13',  encode: function(str) { return caesar(str, 13); } },
        { name: 'Caesar Cipher',
          keys: [
            { label: 'Shift' }
          ],
          encode: caesar,
          decode: function(str, rot) {
            if(rot === '' || isNaN(+rot)) throw new Error('"Shift" must be a number.');
            return caesar(str, -rot);
          }
        },
        { name: 'Atbash Cipher',
          encode: function(str) {
            return str.replace(/[a-z]/g, function(x) {
              return String.fromCharCode('a'.charCodeAt(0) * 2 + 25 - x.charCodeAt(0));
            }).replace(/[A-Z]/g, function(x) {
              return String.fromCharCode('A'.charCodeAt(0) * 2 + 25 - x.charCodeAt(0));
            });
          }
        },
        { name: 'Vigenère Cipher',
          keys: [
            { label: 'Key' }
          ],
          encode: function(str, key) {
            if(key === '') throw new Error('Key cannot be empty.');
            if(key.match(/[^a-zA-Z ]/)) throw new Error('Key can only contain letters.');
            key = key.toLowerCase().split(' ').join('');
            var k = 0;
            var a = 'a'.charCodeAt(0);
            return str.replace(/[a-zA-Z]/g, function(x) {
              var lower = x === x.toLowerCase();
              x = String.fromCharCode((x.toLowerCase().charCodeAt(0) - a + key.charCodeAt((k++)%key.length) - a) % 26 + a);
              return lower? x: x.toUpperCase();
            });
          },
          decode: function(str, key) {
            if(key === '') throw new Error('Key cannot be empty.');
            if(key.match(/[^a-zA-Z ]/)) throw new Error('Key can only contain letters.');
            key = key.toLowerCase().split(' ').join('');;
            var k = 0;
            var a = 'a'.charCodeAt(0);
            return str.replace(/[a-zA-Z]/g, function(x) {
              var lower = x === x.toLowerCase();
              x = String.fromCharCode((x.toLowerCase().charCodeAt(0) - a - (key.charCodeAt((k++)%key.length) - a) + 26) % 26 + a);
              return lower? x: x.toUpperCase();
            });
          }
        }
      ]
    },
    {
      group: 'Codes',
      desc: "<p><b>Codes</b> are distinct from ciphers in that they don't necessarily serve the purpose of secrecy. On one hand, one would use a cipher to <i>encrypt</i> information, so as to keep it a secret from third parties. <i>Encoding</i> a message, on the other hand, is typically used to store or transmit a message in an environment where words might not be possible or effective. For example, encoding a message using morse code may be appropriate for sending a message through a telegraph line.</p>"
      +"<p>Codes and codebooks may still be used to keep information secret, but they are only effective until a third party learns the code you are using.</p>",
      list: [
        { name: 'A1Z26',
          encode: function(str) {
            return str.replace(/[a-zA-Z]+/g, function(inner) {
              return inner.split('').map(function(x) {
                return x.toLowerCase().charCodeAt(0) - 'a'.charCodeAt(0)
              }).join('-');
            });
          },
          decode: function(str) {
            return str.replace(/([0-9]+\-)*[0-9]+/g, function(inner) {
              return inner.split('-')
              .map(function(x) {
                return String.fromCharCode('a'.charCodeAt(0) + Number(x));
              }).join('');
            });
          }
        },
        { name: 'Binary (ASCII)',
          encode: function(str) {
            if(!/^[\x00-\x7F]*$/.test(str)) throw new Error('Non-ascii characters :(');
            return str.split('').map(function(x) {
              var unpadded = x.charCodeAt(0).toString(2);
              return '00000000'.slice(unpadded.length).concat(unpadded);
            }).join(' ');
          },
          decode: function(str) {
            if(!/^([01]{7,8}[ ,]*)*$/.test(str)) throw new Error('Not sure this is binary');
            return str.split(/[ ,]+/).map(function(x) { return String.fromCharCode(parseInt(x, 2)); }).join('');
          }
        },
        { name: 'Morse Code',
          encode: toMorse,
          decode: fromMorse
        }
      ]
    }
  ];
})();