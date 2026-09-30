/ tests/annotations.q — aimeta @param declarations must name the parameters the lambda actually takes.
/ .
/ An annotation is prose until something checks it. `@param sym` surviving a rename of the lambda's
/ parameter to `s` publishes a signature that does not exist: an agent reading the metadata calls the
/ function with a keyword the code never had, and nothing complains, because aimeta records what the
/ comment says rather than what the code does.
/ .
/ So this suite reads the SHIPPED sources — every .q and .md under public/ — pairs each run of
/ annotation comments with the definition line that follows it, and compares the declared parameter
/ names against the ones between `{[` and `]`. Markdown is included deliberately: the drift that
/ prompted this check was in a documented example, not in code.
/ .
/ NB a solitary "/" line would open a block comment, so every blank comment line here carries a ".".

/ Strip leading and trailing spaces and tabs.
.t.trim:{[s]
  i:where not s in " \t";
  $[0 = count i; ""; s (first i) + til 1 + (last i) - first i] };

/ Where each `{[` begins on a line. Scanned character-wise rather than with `ss`, because both `ss`
/ and `like` read "[" as opening a character class and reject the pattern outright.
.t.lambdaAt:{[line] where ("{" = line) & "[" = 1 _ (line, " ") };

/ The parameter names a lambda declares, read from the first `{[...]}` on the line. Empty for `{[]`.
.t.sigParams:{[line]
  i:.t.lambdaAt line;
  if[0 = count i; :()];
  rest:(2 + first i) _ line;
  j:first where "]" = rest;
  if[null j; :()];
  p:.t.trim j # rest;
  $[0 = count p; (); .t.trim each ";" vs p] };

/ The name in `/ @param NAME {type} description` — the first token after the tag.
.t.paramName:{[line]
  rest:.t.trim 8 _ .t.trim line;                    / drop the leading "/ @param"
  $[0 = count rest; ""; first " " vs rest] };

/ Lines that cannot themselves be a definition: comments, blanks, and markdown fences.
.t.isFiller:{[line]
  t:.t.trim line;
  $[0 = count t; 1b; t like "/*"; 1b; t like "```*"; 1b; 0b] };

/ Each annotated block in one file, as (declared names; the definition line; its 1-based number).
/ Several @param lines in one run resolve to a single block, because they share a definition line.
.t.annotatedBlocks:{[f]
  lines:read0 hsym `$f;
  idx:where lines like "/ @param *";
  if[0 = count idx; :()];
  defOf:{[lines;i]
    k:first where not .t.isFiller each (i + 1) _ lines;
    $[null k; 0N; i + 1 + k] }[lines] each idx;
  keep:where not null defOf;
  if[0 = count keep; :()];
  g:group defOf keep;
  names:.t.paramName each lines idx keep;
  {[lines;names;d;ix] (names ix; lines d; d + 1)}[lines;names] .' flip (key g; value g) };

/ Every shipped .q and .md file. `find` is POSIX, and the driver already shells out for its loads.
.t.annotatedFiles:{[]
  raw:system "find modules demos docs skills tests -type f \\( -name '*.q' -o -name '*.md' \\)";
  raw where 0 < count each raw };

/ Render a name list for the failure message; a bare `sv` over an empty list is not a description.
.t.showParams:{[ps] $[0 = count ps; "no parameters"; "(", (", " sv ps), ")"] };

runTest[`declaredParamsMatchTheLambdaSignature; {[]
  / One (file; block) pair per annotated definition. A file with no annotations contributes `()`,
  / which raze absorbs — so every surviving element is a real pair, never an empty one.
  pairs:raze {[f] {[f;b] (f;b)}[f] each .t.annotatedBlocks f} each .t.annotatedFiles[];
  / A definition with no lambda on its line declares no signature to compare against.
  pairs@:where {[p] 0 < count .t.lambdaAt (p 1) 1} each pairs;
  bad:pairs@:where not {[p] ((p 1) 0) ~ .t.sigParams (p 1) 1} each pairs;
  if[count bad;
    '"@param drift — the declared names do not match the lambda:\n  ",
      "\n  " sv {[p]
        (p 0), ":", (string (p 1) 2), " declares ", (.t.showParams (p 1) 0),
          " but the lambda takes ", .t.showParams .t.sigParams (p 1) 1 } each bad];
  }]

/ The check earns nothing if it silently matches no annotations at all, so pin that the scan actually
/ reaches the demo's two protected functions.
runTest[`theAnnotationScanReachesTheShippedSources; {[]
  blocks:.t.annotatedBlocks "demos/local-assertion/host.q";
  if[2 > count blocks;
    '"expected at least the demo's two annotated functions, found ", string count blocks];
  }]
