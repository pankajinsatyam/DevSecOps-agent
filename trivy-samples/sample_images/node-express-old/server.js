// Tiny Express app used only so the sample image has something to run.
const express = require("express");
const _ = require("lodash");

const app = express();

app.get("/", (req, res) => {
  res.send(_.capitalize("hello from the deliberately unsafe sample image"));
});

app.listen(3000, () => console.log("listening on 3000"));
