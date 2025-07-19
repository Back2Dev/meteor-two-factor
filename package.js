Package.describe({
  name: "mikkelking:two-factor",
  version: "3.0.1",
  summary: "Two-factor authentication for accounts-password",
  git: "https://github.com/Back2Dev/meteor-two-factor.git",
  documentation: "README.md",
})

Package.onUse(function (api) {
  api.versionsFrom(["2.8.0", "3.0"])
  api.use(["ecmascript", "check"])
  api.use("reactive-dict", "client")
  api.use("accounts-password", ["client", "server"])
  api.addFiles("common.js")
  api.addFiles("client.js", "client")
  api.addFiles("server.js", "server")
  api.export("twoFactor")
})

Package.onTest(function (api) {
  api.use("ecmascript")
  api.use("tinytest")
  api.use("mikkelking:two-factor")
  api.addFiles("tests.js")
})
