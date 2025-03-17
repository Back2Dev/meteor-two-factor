import { Match, check } from "meteor/check";

/* globals twoFactor */

twoFactor.options = {};

const generateCode = () => {
  return Array(...Array(6))
    .map(() => {
      return Math.floor(Math.random() * 10);
    })
    .join("");
};

const NonEmptyString = Match.Where((x) => {
  check(x, String);
  return x.length > 0;
});

const userQueryValidator = Match.Where((user) => {
  check(user, {
    id: Match.Optional(NonEmptyString),
    username: Match.Optional(NonEmptyString),
    email: Match.Optional(NonEmptyString),
  });
  if (Object.keys(user).length !== 1) {
    throw new Match.Error("User property must have exactly one field");
  }
  return true;
});

const passwordValidator = { digest: String, algorithm: String };

const invalidLogin = () => {
  return new Meteor.Error(403, "Invalid login credentials");
};

const getFieldName = () => {
  return twoFactor.options.fieldName || "twoFactorCode";
};

Meteor.methods({
  async "twoFactor.getAuthenticationCode"(userQuery, password) {
    check(userQuery, userQueryValidator);
    check(password, passwordValidator);

    const fieldName = getFieldName();

    const user = await Accounts._findUserByQuery(userQuery);
    if (!user) {
      throw invalidLogin();
    }

    const checkPassword = await Accounts._checkPasswordAsync(user, password);
    if (checkPassword.error) {
      throw invalidLogin();
    }

    const code =
      typeof twoFactor.generateCode === "function"
        ? twoFactor.generateCode()
        : generateCode();

    if (typeof twoFactor.sendCode === "function") {
      await twoFactor.sendCode(user, code);
    }

    await Meteor.users.updateAsync(user._id, {
      $set: {
        [fieldName]: code,
      },
    });
  },
  async "twoFactor.verifyCodeAndLogin"(options) {
    check(options, {
      user: userQueryValidator,
      password: passwordValidator,
      code: String,
    });

    const fieldName = getFieldName();

    const user = await Accounts._findUserByQuery(options.user);
    if (!user) {
      throw invalidLogin();
    }

    const checkPassword = await Accounts._checkPasswordAsync(
      user,
      options.password
    );
    if (checkPassword.error) {
      throw invalidLogin();
    }

    if (options.code !== user[fieldName]) {
      throw new Meteor.Error(403, "Invalid code");
    }

    Meteor.users.updateAsync(user._id, {
      $unset: {
        [fieldName]: "",
      },
    });

    return await Accounts._attemptLogin(this, "login", "", {
      type: "2FALogin",
      userId: user._id,
    });
  },
  async "twoFactor.abort"(userQuery, password) {
    check(userQuery, userQueryValidator);
    check(password, passwordValidator);

    const fieldName = getFieldName();

    const user = await Accounts._findUserByQuery(userQuery);
    if (!user) {
      throw invalidLogin();
    }

    const checkPassword = await Accounts._checkPasswordAsync(user, password);
    if (checkPassword.error) {
      throw invalidLogin();
    }

    await Meteor.users.updateAsync(user._id, {
      $unset: {
        [fieldName]: "",
      },
    });
  },
});

Accounts.validateLoginAttempt((options) => {
  const customValidator = () => {
    if (typeof twoFactor.validateLoginAttempt === "function") {
      return twoFactor.validateLoginAttempt(options);
    }
    return false;
  };

  const allowedMethods = ["createUser", "resetPassword", "verifyEmail"];

  if (
    customValidator() ||
    options.type === "resume" ||
    allowedMethods.indexOf(options.methodName) !== -1
  ) {
    return true;
  }

  if (options.type === "2FALogin" && options.methodName === "login") {
    return options.allowed;
  }

  return false;
});
