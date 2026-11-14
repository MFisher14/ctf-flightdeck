// fixture: the puzzle as an object literal in a React Native module
var puzzle = {schema: "huntress.mobile.puzzle.v1", day: 9, codec: "reverse", data: "0FE9D8C7B6A54321-SNA"};
var other = {title: "Fixture", build: 42, debug: false};
function show(p) { return p.codec + ":" + p.data + "été" + "中文"; }
print(show(puzzle), other.title);
