// FROZEN verbatim copies of the three inline squarify implementations
// that the one squarify (src/pplns/squarify.ts) replaced, taken from
// master 623f7d9a. Used only by tests/unit/squarify-parity.test.ts to
// prove the swap leaves every tile where it was. Do not edit or "fix"
// these: they are the reference.

// web-static/dashboard.html:7367-7447 — `defrag` hover-zoom treemap.
export const dashboardHover = {
            // Squarified treemap: place items into rows trying to keep aspect ratio ~1
            treemap: function(data, x, y, w, h) {
                var rects = [];
                var items = data.map(function(d) { return { addr: d.addr, pct: d.pct, area: d.pct }; });
                this._layoutRow(items, x, y, w, h, rects);
                return rects;
            },

            _layoutRow: function(items, x, y, w, h, rects) {
                if (items.length === 0) return;
                var totalArea = 0;
                items.forEach(function(it) { totalArea += it.area; });
                if (totalArea <= 0) return;

                // Lay out along the shorter axis
                var vertical = w >= h;
                var mainSize = vertical ? h : w;
                var crossSize = vertical ? w : h;

                var row = [];
                var rowArea = 0;
                var remaining = items.slice();

                while (remaining.length > 0) {
                    row.push(remaining[0]);
                    rowArea += remaining[0].area;
                    remaining.shift();

                    if (remaining.length === 0) break;

                    // Check if adding next item worsens aspect ratio
                    var nextArea = rowArea + remaining[0].area;
                    var rowFraction = rowArea / totalArea;
                    var nextFraction = nextArea / totalArea;
                    var stripSize = rowFraction * crossSize;
                    var nextStripSize = nextFraction * crossSize;

                    var worstCurrent = this._worstAspect(row, rowArea, stripSize, mainSize, totalArea);
                    var testRow = row.concat([remaining[0]]);
                    var worstNext = this._worstAspect(testRow, nextArea, nextStripSize, mainSize, totalArea);

                    if (worstNext > worstCurrent && row.length >= 1) {
                        // Current row is better, lay it out
                        break;
                    }
                }

                // Lay out the row
                var rowFraction = rowArea / totalArea;
                var stripSize = Math.max(1, rowFraction * crossSize);
                var offset = 0;
                for (var i = 0; i < row.length; i++) {
                    var itemFraction = row[i].area / rowArea;
                    var itemSize = itemFraction * mainSize;
                    if (vertical) {
                        rects.push({ x: x, y: y + offset, w: stripSize, h: itemSize, addr: row[i].addr, pct: row[i].pct });
                    } else {
                        rects.push({ x: x + offset, y: y, w: itemSize, h: stripSize, addr: row[i].addr, pct: row[i].pct });
                    }
                    offset += itemSize;
                }

                // Recurse on remaining
                if (remaining.length > 0) {
                    if (vertical) {
                        this._layoutRow(remaining, x + stripSize, y, w - stripSize, h, rects);
                    } else {
                        this._layoutRow(remaining, x, y + stripSize, w, h - stripSize, rects);
                    }
                }
            },

            _worstAspect: function(row, rowArea, stripSize, mainSize, totalArea) {
                var worst = 0;
                for (var i = 0; i < row.length; i++) {
                    var itemSize = (row[i].area / rowArea) * mainSize;
                    var aspect = Math.max(itemSize / stripSize, stripSize / itemSize);
                    if (aspect > worst) worst = aspect;
                }
                return worst;
            },
};

// web-static/dashboard.html:7727-7760 — renderMainPPLNS ("PPLNS
// Distribution") layout. `entries` are the sorted rows it builds.
export function dashboardMain(entries, w, h) {
                var rects = [];
                var items = entries.map(function(d) { return { addr:d.addr, pct:d.pct, amt:d.amt, doge:d.doge, dogeAddr:d.dogeAddr, area:d.pct }; });
                function tmLayout(items, x, y, w, h) {
                    if (!items.length || w <= 0 || h <= 0) return;
                    var tot = 0; items.forEach(function(it) { tot += it.area; });
                    if (tot <= 0) return;
                    var vert = w >= h, main = vert ? h : w, cross = vert ? w : h;
                    var row = [], rowA = 0, rem = items.slice();
                    while (rem.length) {
                        row.push(rem[0]); rowA += rem[0].area; rem.shift();
                        if (!rem.length) break;
                        var sNow = (rowA/tot)*cross, sNext = ((rowA+rem[0].area)/tot)*cross;
                        var wNow = 0, wNext = 0;
                        row.forEach(function(r) { var s=(r.area/rowA)*main; var a=Math.max(s/sNow,sNow/s); if(a>wNow)wNow=a; });
                        var testRow = row.concat([rem[0]]), testA = rowA+rem[0].area;
                        testRow.forEach(function(r) { var s=(r.area/testA)*main; var a=Math.max(s/sNext,sNext/s); if(a>wNext)wNext=a; });
                        if (wNext > wNow && row.length >= 1) break;
                    }
                    var strip = Math.max(1, (rowA/tot)*cross), off = 0;
                    for (var i = 0; i < row.length; i++) {
                        var sz = (row[i].area/rowA)*main;
                        var r = vert
                            ? { x:x, y:y+off, w:strip, h:sz }
                            : { x:x+off, y:y, w:sz, h:strip };
                        r.addr=row[i].addr; r.pct=row[i].pct; r.amt=row[i].amt; r.doge=row[i].doge; r.dogeAddr=row[i].dogeAddr;
                        rects.push(r);
                        off += sz;
                    }
                    if (rem.length) {
                        if (vert) tmLayout(rem, x+strip, y, w-strip, h);
                        else tmLayout(rem, x, y+strip, w, h-strip);
                    }
                }
                tmLayout(items, 0, 0, w, h);
                return rects;
}

// web-static/share.html:989-1039 — share page PPLNS treemap.
        function pplnsTreemap(data, x, y, w, h) {
            var rects = [];
            var items = data.map(function(d) { return { addr: d.addr, pct: d.pct, amt: d.amt, doge: d.doge || 0, dogeAddr: d.dogeAddr || '', area: d.pct }; });
            _tmLayout(items, x, y, w, h, rects);
            return rects;
        }

        function _tmLayout(items, x, y, w, h, rects) {
            if (items.length === 0 || w <= 0 || h <= 0) return;
            var totalArea = 0;
            items.forEach(function(it) { totalArea += it.area; });
            if (totalArea <= 0) return;
            var vertical = w >= h;
            var mainSize = vertical ? h : w;
            var crossSize = vertical ? w : h;
            var row = [], rowArea = 0, remaining = items.slice();

            while (remaining.length > 0) {
                row.push(remaining[0]);
                rowArea += remaining[0].area;
                remaining.shift();
                if (remaining.length === 0) break;
                var stripNow = (rowArea / totalArea) * crossSize;
                var stripNext = ((rowArea + remaining[0].area) / totalArea) * crossSize;
                var worstNow = _tmWorst(row, rowArea, stripNow, mainSize);
                var worstNext = _tmWorst(row.concat([remaining[0]]), rowArea + remaining[0].area, stripNext, mainSize);
                if (worstNext > worstNow && row.length >= 1) break;
            }
            var stripSize = Math.max(1, (rowArea / totalArea) * crossSize);
            var offset = 0;
            for (var i = 0; i < row.length; i++) {
                var sz = (row[i].area / rowArea) * mainSize;
                if (vertical) rects.push({ x: x, y: y+offset, w: stripSize, h: sz, addr: row[i].addr, pct: row[i].pct, amt: row[i].amt, doge: row[i].doge, dogeAddr: row[i].dogeAddr });
                else rects.push({ x: x+offset, y: y, w: sz, h: stripSize, addr: row[i].addr, pct: row[i].pct, amt: row[i].amt, doge: row[i].doge, dogeAddr: row[i].dogeAddr });
                offset += sz;
            }
            if (remaining.length > 0) {
                if (vertical) _tmLayout(remaining, x+stripSize, y, w-stripSize, h, rects);
                else _tmLayout(remaining, x, y+stripSize, w, h-stripSize, rects);
            }
        }

        function _tmWorst(row, rowArea, strip, main) {
            var worst = 0;
            for (var i = 0; i < row.length; i++) {
                var sz = (row[i].area / rowArea) * main;
                var a = Math.max(sz / strip, strip / sz);
                if (a > worst) worst = a;
            }
            return worst;
        }
export { pplnsTreemap as sharePage };
