const out = [];
const specials = [0, -0, 1, -1, 0.1, 1e21, 1e20, 1e-7, 1e-6, 5e-324, 1.7976931348623157e308,
                  1e16, 123456789012345678, 3.141592653589793, 2/3, 1e-320, 9007199254740991];
for (const v of specials) out.push([v, JSON.stringify(v)]);
let seed = 12345;
function rnd(){ seed = (seed * 1103515245 + 12345) & 0x7fffffff; return seed / 0x7fffffff; }
for (let i=0;i<3000;i++){
  const e = Math.floor(rnd()*60)-30;
  const v = (rnd()*2-1) * Math.pow(10, e);
  out.push([v, JSON.stringify(v)]);
}
console.log(JSON.stringify(out));
