# Tasks — ENG-1 network-content classify
- [x] ContentResolver + contentHolder seam; classifyStage content branch (worker inline Content).
- [x] Engine.SetContentResolver (default none → D134 preserved).
- [x] Refactor the worker-call/classification-build into a shared classify() helper.
- [x] Test: SMTP body → worker Content → CPF hit + audit; DNS → no content call; pathless file → error; no matched_text (D29).
- [x] Mutation: disable the content branch → the SMTP body never reaches the worker (test fails).
- [x] make all clean; docs D147; sync; archive; commit; push; memory.
