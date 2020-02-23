"use strict";

var _node = require("parse/node");

var _lodash = _interopRequireDefault(require("lodash"));

var _intersect = _interopRequireDefault(require("intersect"));

var _deepcopy = _interopRequireDefault(require("deepcopy"));

var _logger = _interopRequireDefault(require("../logger"));

var SchemaController = _interopRequireWildcard(require("./SchemaController"));

var _StorageAdapter = require("../Adapters/Storage/StorageAdapter");

function _getRequireWildcardCache() { if (typeof WeakMap !== "function") return null; var cache = new WeakMap(); _getRequireWildcardCache = function () { return cache; }; return cache; }

function _interopRequireWildcard(obj) { if (obj && obj.__esModule) { return obj; } if (obj === null || typeof obj !== "object" && typeof obj !== "function") { return { default: obj }; } var cache = _getRequireWildcardCache(); if (cache && cache.has(obj)) { return cache.get(obj); } var newObj = {}; var hasPropertyDescriptor = Object.defineProperty && Object.getOwnPropertyDescriptor; for (var key in obj) { if (Object.prototype.hasOwnProperty.call(obj, key)) { var desc = hasPropertyDescriptor ? Object.getOwnPropertyDescriptor(obj, key) : null; if (desc && (desc.get || desc.set)) { Object.defineProperty(newObj, key, desc); } else { newObj[key] = obj[key]; } } } newObj.default = obj; if (cache) { cache.set(obj, newObj); } return newObj; }

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

function ownKeys(object, enumerableOnly) { var keys = Object.keys(object); if (Object.getOwnPropertySymbols) { var symbols = Object.getOwnPropertySymbols(object); if (enumerableOnly) symbols = symbols.filter(function (sym) { return Object.getOwnPropertyDescriptor(object, sym).enumerable; }); keys.push.apply(keys, symbols); } return keys; }

function _objectSpread(target) { for (var i = 1; i < arguments.length; i++) { var source = arguments[i] != null ? arguments[i] : {}; if (i % 2) { ownKeys(Object(source), true).forEach(function (key) { _defineProperty(target, key, source[key]); }); } else if (Object.getOwnPropertyDescriptors) { Object.defineProperties(target, Object.getOwnPropertyDescriptors(source)); } else { ownKeys(Object(source)).forEach(function (key) { Object.defineProperty(target, key, Object.getOwnPropertyDescriptor(source, key)); }); } } return target; }

function _defineProperty(obj, key, value) { if (key in obj) { Object.defineProperty(obj, key, { value: value, enumerable: true, configurable: true, writable: true }); } else { obj[key] = value; } return obj; }

function _objectWithoutProperties(source, excluded) { if (source == null) return {}; var target = _objectWithoutPropertiesLoose(source, excluded); var key, i; if (Object.getOwnPropertySymbols) { var sourceSymbolKeys = Object.getOwnPropertySymbols(source); for (i = 0; i < sourceSymbolKeys.length; i++) { key = sourceSymbolKeys[i]; if (excluded.indexOf(key) >= 0) continue; if (!Object.prototype.propertyIsEnumerable.call(source, key)) continue; target[key] = source[key]; } } return target; }

function _objectWithoutPropertiesLoose(source, excluded) { if (source == null) return {}; var target = {}; var sourceKeys = Object.keys(source); var key, i; for (i = 0; i < sourceKeys.length; i++) { key = sourceKeys[i]; if (excluded.indexOf(key) >= 0) continue; target[key] = source[key]; } return target; }

function addWriteACL(query, acl) {
  const newQuery = _lodash.default.cloneDeep(query); //Can't be any existing '_wperm' query, we don't allow client queries on that, no need to $and


  newQuery._wperm = {
    $in: [null, ...acl]
  };
  return newQuery;
}

function addReadACL(query, acl) {
  const newQuery = _lodash.default.cloneDeep(query); //Can't be any existing '_rperm' query, we don't allow client queries on that, no need to $and


  newQuery._rperm = {
    $in: [null, '*', ...acl]
  };
  return newQuery;
} // Transforms a REST API formatted ACL object to our two-field mongo format.


const transformObjectACL = (_ref) => {
  let {
    ACL
  } = _ref,
      result = _objectWithoutProperties(_ref, ["ACL"]);

  if (!ACL) {
    return result;
  }

  result._wperm = [];
  result._rperm = [];

  for (const entry in ACL) {
    if (ACL[entry].read) {
      result._rperm.push(entry);
    }

    if (ACL[entry].write) {
      result._wperm.push(entry);
    }
  }

  return result;
};

const specialQuerykeys = ['$and', '$or', '$nor', '_rperm', '_wperm', '_perishable_token', '_email_verify_token', '_email_verify_token_expires_at', '_account_lockout_expires_at', '_failed_login_count'];

const isSpecialQueryKey = key => {
  return specialQuerykeys.indexOf(key) >= 0;
};

const validateQuery = (query, skipMongoDBServer13732Workaround) => {
  if (query.ACL) {
    throw new _node.Parse.Error(_node.Parse.Error.INVALID_QUERY, 'Cannot query on ACL.');
  }

  if (query.$or) {
    if (query.$or instanceof Array) {
      query.$or.forEach(el => validateQuery(el, skipMongoDBServer13732Workaround));

      if (!skipMongoDBServer13732Workaround) {
        /* In MongoDB 3.2 & 3.4, $or queries which are not alone at the top
         * level of the query can not make efficient use of indexes due to a
         * long standing bug known as SERVER-13732.
         *
         * This bug was fixed in MongoDB version 3.6.
         *
         * For versions pre-3.6, the below logic produces a substantial
         * performance improvement inside the database by avoiding the bug.
         *
         * For versions 3.6 and above, there is no performance improvement and
         * the logic is unnecessary. Some query patterns are even slowed by
         * the below logic, due to the bug having been fixed and better
         * query plans being chosen.
         *
         * When versions before 3.4 are no longer supported by this project,
         * this logic, and the accompanying `skipMongoDBServer13732Workaround`
         * flag, can be removed.
         *
         * This block restructures queries in which $or is not the sole top
         * level element by moving all other top-level predicates inside every
         * subdocument of the $or predicate, allowing MongoDB's query planner
         * to make full use of the most relevant indexes.
         *
         * EG:      {$or: [{a: 1}, {a: 2}], b: 2}
         * Becomes: {$or: [{a: 1, b: 2}, {a: 2, b: 2}]}
         *
         * The only exceptions are $near and $nearSphere operators, which are
         * constrained to only 1 operator per query. As a result, these ops
         * remain at the top level
         *
         * https://jira.mongodb.org/browse/SERVER-13732
         * https://github.com/parse-community/parse-server/issues/3767
         */
        Object.keys(query).forEach(key => {
          const noCollisions = !query.$or.some(subq => Object.prototype.hasOwnProperty.call(subq, key));
          let hasNears = false;

          if (query[key] != null && typeof query[key] == 'object') {
            hasNears = '$near' in query[key] || '$nearSphere' in query[key];
          }

          if (key != '$or' && noCollisions && !hasNears) {
            query.$or.forEach(subquery => {
              subquery[key] = query[key];
            });
            delete query[key];
          }
        });
        query.$or.forEach(el => validateQuery(el, skipMongoDBServer13732Workaround));
      }
    } else {
      throw new _node.Parse.Error(_node.Parse.Error.INVALID_QUERY, 'Bad $or format - use an array value.');
    }
  }

  if (query.$and) {
    if (query.$and instanceof Array) {
      query.$and.forEach(el => validateQuery(el, skipMongoDBServer13732Workaround));
    } else {
      throw new _node.Parse.Error(_node.Parse.Error.INVALID_QUERY, 'Bad $and format - use an array value.');
    }
  }

  if (query.$nor) {
    if (query.$nor instanceof Array && query.$nor.length > 0) {
      query.$nor.forEach(el => validateQuery(el, skipMongoDBServer13732Workaround));
    } else {
      throw new _node.Parse.Error(_node.Parse.Error.INVALID_QUERY, 'Bad $nor format - use an array of at least 1 value.');
    }
  }

  Object.keys(query).forEach(key => {
    if (query && query[key] && query[key].$regex) {
      if (typeof query[key].$options === 'string') {
        if (!query[key].$options.match(/^[imxs]+$/)) {
          throw new _node.Parse.Error(_node.Parse.Error.INVALID_QUERY, `Bad $options value for query: ${query[key].$options}`);
        }
      }
    }

    if (!isSpecialQueryKey(key) && !key.match(/^[a-zA-Z][a-zA-Z0-9_\.]*$/)) {
      throw new _node.Parse.Error(_node.Parse.Error.INVALID_KEY_NAME, `Invalid key name: ${key}`);
    }
  });
}; // Filters out any data that shouldn't be on this REST-formatted object.


const filterSensitiveData = (isMaster, aclGroup, auth, operation, schema, className, protectedFields, object) => {
  let userId = null;
  if (auth && auth.user) userId = auth.user.id; // replace protectedFields when using pointer-permissions

  const perms = schema.getClassLevelPermissions(className);

  if (perms) {
    const isReadOperation = ['get', 'find'].indexOf(operation) > -1;

    if (isReadOperation && perms.protectedFields) {
      // extract protectedFields added with the pointer-permission prefix
      const protectedFieldsPointerPerm = Object.keys(perms.protectedFields).filter(key => key.startsWith('userField:')).map(key => {
        return {
          key: key.substring(10),
          value: perms.protectedFields[key]
        };
      });
      const newProtectedFields = [];
      let overrideProtectedFields = false; // check if the object grants the current user access based on the extracted fields

      protectedFieldsPointerPerm.forEach(pointerPerm => {
        let pointerPermIncludesUser = false;
        const readUserFieldValue = object[pointerPerm.key];

        if (readUserFieldValue) {
          if (Array.isArray(readUserFieldValue)) {
            pointerPermIncludesUser = readUserFieldValue.some(user => user.objectId && user.objectId === userId);
          } else {
            pointerPermIncludesUser = readUserFieldValue.objectId && readUserFieldValue.objectId === userId;
          }
        }

        if (pointerPermIncludesUser) {
          overrideProtectedFields = true;
          newProtectedFields.push(...pointerPerm.value);
        }
      }); // if atleast one pointer-permission affected the current user override the protectedFields

      if (overrideProtectedFields) protectedFields = newProtectedFields;
    }
  }

  const isUserClass = className === '_User';
  /* special treat for the user class: don't filter protectedFields if currently loggedin user is
  the retrieved user */

  if (!(isUserClass && userId && object.objectId === userId)) protectedFields && protectedFields.forEach(k => delete object[k]);

  if (!isUserClass) {
    return object;
  }

  object.password = object._hashed_password;
  delete object._hashed_password;
  delete object.sessionToken;

  if (isMaster) {
    return object;
  }

  delete object._email_verify_token;
  delete object._perishable_token;
  delete object._perishable_token_expires_at;
  delete object._tombstone;
  delete object._email_verify_token_expires_at;
  delete object._failed_login_count;
  delete object._account_lockout_expires_at;
  delete object._password_changed_at;
  delete object._password_history;

  if (aclGroup.indexOf(object.objectId) > -1) {
    return object;
  }

  delete object.authData;
  return object;
};

// Runs an update on the database.
// Returns a promise for an object with the new values for field
// modifications that don't know their results ahead of time, like
// 'increment'.
// Options:
//   acl:  a list of strings. If the object to be updated has an ACL,
//         one of the provided strings must provide the caller with
//         write permissions.
const specialKeysForUpdate = ['_hashed_password', '_perishable_token', '_email_verify_token', '_email_verify_token_expires_at', '_account_lockout_expires_at', '_failed_login_count', '_perishable_token_expires_at', '_password_changed_at', '_password_history'];

const isSpecialUpdateKey = key => {
  return specialKeysForUpdate.indexOf(key) >= 0;
};

function expandResultOnKeyPath(object, key, value) {
  if (key.indexOf('.') < 0) {
    object[key] = value[key];
    return object;
  }

  const path = key.split('.');
  const firstKey = path[0];
  const nextPath = path.slice(1).join('.');
  object[firstKey] = expandResultOnKeyPath(object[firstKey] || {}, nextPath, value[firstKey]);
  delete object[key];
  return object;
}

function sanitizeDatabaseResult(originalObject, result) {
  const response = {};

  if (!result) {
    return Promise.resolve(response);
  }

  Object.keys(originalObject).forEach(key => {
    const keyUpdate = originalObject[key]; // determine if that was an op

    if (keyUpdate && typeof keyUpdate === 'object' && keyUpdate.__op && ['Add', 'AddUnique', 'Remove', 'Increment'].indexOf(keyUpdate.__op) > -1) {
      // only valid ops that produce an actionable result
      // the op may have happend on a keypath
      expandResultOnKeyPath(response, key, result);
    }
  });
  return Promise.resolve(response);
}

function joinTableName(className, key) {
  return `_Join:${key}:${className}`;
}

const flattenUpdateOperatorsForCreate = object => {
  for (const key in object) {
    if (object[key] && object[key].__op) {
      switch (object[key].__op) {
        case 'Increment':
          if (typeof object[key].amount !== 'number') {
            throw new _node.Parse.Error(_node.Parse.Error.INVALID_JSON, 'objects to add must be an array');
          }

          object[key] = object[key].amount;
          break;

        case 'Add':
          if (!(object[key].objects instanceof Array)) {
            throw new _node.Parse.Error(_node.Parse.Error.INVALID_JSON, 'objects to add must be an array');
          }

          object[key] = object[key].objects;
          break;

        case 'AddUnique':
          if (!(object[key].objects instanceof Array)) {
            throw new _node.Parse.Error(_node.Parse.Error.INVALID_JSON, 'objects to add must be an array');
          }

          object[key] = object[key].objects;
          break;

        case 'Remove':
          if (!(object[key].objects instanceof Array)) {
            throw new _node.Parse.Error(_node.Parse.Error.INVALID_JSON, 'objects to add must be an array');
          }

          object[key] = [];
          break;

        case 'Delete':
          delete object[key];
          break;

        default:
          throw new _node.Parse.Error(_node.Parse.Error.COMMAND_UNAVAILABLE, `The ${object[key].__op} operator is not supported yet.`);
      }
    }
  }
};

const transformAuthData = (className, object, schema) => {
  if (object.authData && className === '_User') {
    Object.keys(object.authData).forEach(provider => {
      const providerData = object.authData[provider];
      const fieldName = `_auth_data_${provider}`;

      if (providerData == null) {
        object[fieldName] = {
          __op: 'Delete'
        };
      } else {
        object[fieldName] = providerData;
        schema.fields[fieldName] = {
          type: 'Object'
        };
      }
    });
    delete object.authData;
  }
}; // Transforms a Database format ACL to a REST API format ACL


const untransformObjectACL = (_ref2) => {
  let {
    _rperm,
    _wperm
  } = _ref2,
      output = _objectWithoutProperties(_ref2, ["_rperm", "_wperm"]);

  if (_rperm || _wperm) {
    output.ACL = {};

    (_rperm || []).forEach(entry => {
      if (!output.ACL[entry]) {
        output.ACL[entry] = {
          read: true
        };
      } else {
        output.ACL[entry]['read'] = true;
      }
    });

    (_wperm || []).forEach(entry => {
      if (!output.ACL[entry]) {
        output.ACL[entry] = {
          write: true
        };
      } else {
        output.ACL[entry]['write'] = true;
      }
    });
  }

  return output;
};
/**
 * When querying, the fieldName may be compound, extract the root fieldName
 *     `temperature.celsius` becomes `temperature`
 * @param {string} fieldName that may be a compound field name
 * @returns {string} the root name of the field
 */


const getRootFieldName = fieldName => {
  return fieldName.split('.')[0];
};

const relationSchema = {
  fields: {
    relatedId: {
      type: 'String'
    },
    owningId: {
      type: 'String'
    }
  }
};

class DatabaseController {
  constructor(adapter, schemaCache, skipMongoDBServer13732Workaround) {
    this.adapter = adapter;
    this.schemaCache = schemaCache; // We don't want a mutable this.schema, because then you could have
    // one request that uses different schemas for different parts of
    // it. Instead, use loadSchema to get a schema.

    this.schemaPromise = null;
    this.skipMongoDBServer13732Workaround = skipMongoDBServer13732Workaround;
    this._transactionalSession = null;
  }

  collectionExists(className) {
    return this.adapter.classExists(className);
  }

  purgeCollection(className) {
    return this.loadSchema().then(schemaController => schemaController.getOneSchema(className)).then(schema => this.adapter.deleteObjectsByQuery(className, schema, {}));
  }

  validateClassName(className) {
    if (!SchemaController.classNameIsValid(className)) {
      return Promise.reject(new _node.Parse.Error(_node.Parse.Error.INVALID_CLASS_NAME, 'invalid className: ' + className));
    }

    return Promise.resolve();
  } // Returns a promise for a schemaController.


  loadSchema(options = {
    clearCache: false
  }) {
    if (this.schemaPromise != null) {
      return this.schemaPromise;
    }

    this.schemaPromise = SchemaController.load(this.adapter, this.schemaCache, options);
    this.schemaPromise.then(() => delete this.schemaPromise, () => delete this.schemaPromise);
    return this.loadSchema(options);
  }

  loadSchemaIfNeeded(schemaController, options = {
    clearCache: false
  }) {
    return schemaController ? Promise.resolve(schemaController) : this.loadSchema(options);
  } // Returns a promise for the classname that is related to the given
  // classname through the key.
  // TODO: make this not in the DatabaseController interface


  redirectClassNameForKey(className, key) {
    return this.loadSchema().then(schema => {
      var t = schema.getExpectedType(className, key);

      if (t != null && typeof t !== 'string' && t.type === 'Relation') {
        return t.targetClass;
      }

      return className;
    });
  } // Uses the schema to validate the object (REST API format).
  // Returns a promise that resolves to the new schema.
  // This does not update this.schema, because in a situation like a
  // batch request, that could confuse other users of the schema.


  validateObject(className, object, query, runOptions) {
    let schema;
    const acl = runOptions.acl;
    const isMaster = acl === undefined;
    var aclGroup = acl || [];
    return this.loadSchema().then(s => {
      schema = s;

      if (isMaster) {
        return Promise.resolve();
      }

      return this.canAddField(schema, className, object, aclGroup, runOptions);
    }).then(() => {
      return schema.validateObject(className, object, query);
    });
  }

  update(className, query, update, {
    acl,
    many,
    upsert,
    addsField
  } = {}, skipSanitization = false, validateOnly = false, validSchemaController) {
    const originalQuery = query;
    const originalUpdate = update; // Make a copy of the object, so we don't mutate the incoming data.

    update = (0, _deepcopy.default)(update);
    var relationUpdates = [];
    var isMaster = acl === undefined;
    var aclGroup = acl || [];
    return this.loadSchemaIfNeeded(validSchemaController).then(schemaController => {
      return (isMaster ? Promise.resolve() : schemaController.validatePermission(className, aclGroup, 'update')).then(() => {
        relationUpdates = this.collectRelationUpdates(className, originalQuery.objectId, update);

        if (!isMaster) {
          query = this.addPointerPermissions(schemaController, className, 'update', query, aclGroup);

          if (addsField) {
            query = {
              $and: [query, this.addPointerPermissions(schemaController, className, 'addField', query, aclGroup)]
            };
          }
        }

        if (!query) {
          return Promise.resolve();
        }

        if (acl) {
          query = addWriteACL(query, acl);
        }

        validateQuery(query, this.skipMongoDBServer13732Workaround);
        return schemaController.getOneSchema(className, true).catch(error => {
          // If the schema doesn't exist, pretend it exists with no fields. This behavior
          // will likely need revisiting.
          if (error === undefined) {
            return {
              fields: {}
            };
          }

          throw error;
        }).then(schema => {
          Object.keys(update).forEach(fieldName => {
            if (fieldName.match(/^authData\.([a-zA-Z0-9_]+)\.id$/)) {
              throw new _node.Parse.Error(_node.Parse.Error.INVALID_KEY_NAME, `Invalid field name for update: ${fieldName}`);
            }

            const rootFieldName = getRootFieldName(fieldName);

            if (!SchemaController.fieldNameIsValid(rootFieldName) && !isSpecialUpdateKey(rootFieldName)) {
              throw new _node.Parse.Error(_node.Parse.Error.INVALID_KEY_NAME, `Invalid field name for update: ${fieldName}`);
            }
          });

          for (const updateOperation in update) {
            if (update[updateOperation] && typeof update[updateOperation] === 'object' && Object.keys(update[updateOperation]).some(innerKey => innerKey.includes('$') || innerKey.includes('.'))) {
              throw new _node.Parse.Error(_node.Parse.Error.INVALID_NESTED_KEY, "Nested keys should not contain the '$' or '.' characters");
            }
          }

          update = transformObjectACL(update);
          transformAuthData(className, update, schema);

          if (validateOnly) {
            return {};
          }

          if (many) {
            return this.adapter.updateObjectsByQuery(className, schema, query, update, this._transactionalSession);
          } else if (upsert) {
            return this.adapter.upsertOneObject(className, schema, query, update, this._transactionalSession);
          } else {
            return this.adapter.findOneAndUpdate(className, schema, query, update, this._transactionalSession);
          }
        });
      }).then(result => {
        if (!result) {
          throw new _node.Parse.Error(_node.Parse.Error.OBJECT_NOT_FOUND, 'Object not found.');
        }

        if (validateOnly) {
          return result;
        }

        return this.handleRelationUpdates(className, originalQuery.objectId, update, relationUpdates).then(() => {
          return result;
        });
      }).then(result => {
        if (skipSanitization) {
          return Promise.resolve(result);
        }

        return sanitizeDatabaseResult(originalUpdate, result);
      });
    });
  } // Collect all relation-updating operations from a REST-format update.
  // Returns a list of all relation updates to perform
  // This mutates update.


  collectRelationUpdates(className, objectId, update) {
    var ops = [];
    var deleteMe = [];
    objectId = update.objectId || objectId;

    var process = (op, key) => {
      if (!op) {
        return;
      }

      if (op.__op == 'AddRelation') {
        ops.push({
          key,
          op
        });
        deleteMe.push(key);
      }

      if (op.__op == 'RemoveRelation') {
        ops.push({
          key,
          op
        });
        deleteMe.push(key);
      }

      if (op.__op == 'Batch') {
        for (var x of op.ops) {
          process(x, key);
        }
      }
    };

    for (const key in update) {
      process(update[key], key);
    }

    for (const key of deleteMe) {
      delete update[key];
    }

    return ops;
  } // Processes relation-updating operations from a REST-format update.
  // Returns a promise that resolves when all updates have been performed


  handleRelationUpdates(className, objectId, update, ops) {
    var pending = [];
    objectId = update.objectId || objectId;
    ops.forEach(({
      key,
      op
    }) => {
      if (!op) {
        return;
      }

      if (op.__op == 'AddRelation') {
        for (const object of op.objects) {
          pending.push(this.addRelation(key, className, objectId, object.objectId));
        }
      }

      if (op.__op == 'RemoveRelation') {
        for (const object of op.objects) {
          pending.push(this.removeRelation(key, className, objectId, object.objectId));
        }
      }
    });
    return Promise.all(pending);
  } // Adds a relation.
  // Returns a promise that resolves successfully iff the add was successful.


  addRelation(key, fromClassName, fromId, toId) {
    const doc = {
      relatedId: toId,
      owningId: fromId
    };
    return this.adapter.upsertOneObject(`_Join:${key}:${fromClassName}`, relationSchema, doc, doc, this._transactionalSession);
  } // Removes a relation.
  // Returns a promise that resolves successfully iff the remove was
  // successful.


  removeRelation(key, fromClassName, fromId, toId) {
    var doc = {
      relatedId: toId,
      owningId: fromId
    };
    return this.adapter.deleteObjectsByQuery(`_Join:${key}:${fromClassName}`, relationSchema, doc, this._transactionalSession).catch(error => {
      // We don't care if they try to delete a non-existent relation.
      if (error.code == _node.Parse.Error.OBJECT_NOT_FOUND) {
        return;
      }

      throw error;
    });
  } // Removes objects matches this query from the database.
  // Returns a promise that resolves successfully iff the object was
  // deleted.
  // Options:
  //   acl:  a list of strings. If the object to be updated has an ACL,
  //         one of the provided strings must provide the caller with
  //         write permissions.


  destroy(className, query, {
    acl
  } = {}, validSchemaController) {
    const isMaster = acl === undefined;
    const aclGroup = acl || [];
    return this.loadSchemaIfNeeded(validSchemaController).then(schemaController => {
      return (isMaster ? Promise.resolve() : schemaController.validatePermission(className, aclGroup, 'delete')).then(() => {
        if (!isMaster) {
          query = this.addPointerPermissions(schemaController, className, 'delete', query, aclGroup);

          if (!query) {
            throw new _node.Parse.Error(_node.Parse.Error.OBJECT_NOT_FOUND, 'Object not found.');
          }
        } // delete by query


        if (acl) {
          query = addWriteACL(query, acl);
        }

        validateQuery(query, this.skipMongoDBServer13732Workaround);
        return schemaController.getOneSchema(className).catch(error => {
          // If the schema doesn't exist, pretend it exists with no fields. This behavior
          // will likely need revisiting.
          if (error === undefined) {
            return {
              fields: {}
            };
          }

          throw error;
        }).then(parseFormatSchema => this.adapter.deleteObjectsByQuery(className, parseFormatSchema, query, this._transactionalSession)).catch(error => {
          // When deleting sessions while changing passwords, don't throw an error if they don't have any sessions.
          if (className === '_Session' && error.code === _node.Parse.Error.OBJECT_NOT_FOUND) {
            return Promise.resolve({});
          }

          throw error;
        });
      });
    });
  } // Inserts an object into the database.
  // Returns a promise that resolves successfully iff the object saved.


  create(className, object, {
    acl
  } = {}, validateOnly = false, validSchemaController) {
    // Make a copy of the object, so we don't mutate the incoming data.
    const originalObject = object;
    object = transformObjectACL(object);
    object.createdAt = {
      iso: object.createdAt,
      __type: 'Date'
    };
    object.updatedAt = {
      iso: object.updatedAt,
      __type: 'Date'
    };
    var isMaster = acl === undefined;
    var aclGroup = acl || [];
    const relationUpdates = this.collectRelationUpdates(className, null, object);
    return this.validateClassName(className).then(() => this.loadSchemaIfNeeded(validSchemaController)).then(schemaController => {
      return (isMaster ? Promise.resolve() : schemaController.validatePermission(className, aclGroup, 'create')).then(() => schemaController.enforceClassExists(className)).then(() => schemaController.getOneSchema(className, true)).then(schema => {
        transformAuthData(className, object, schema);
        flattenUpdateOperatorsForCreate(object);

        if (validateOnly) {
          return {};
        }

        return this.adapter.createObject(className, SchemaController.convertSchemaToAdapterSchema(schema), object, this._transactionalSession);
      }).then(result => {
        if (validateOnly) {
          return originalObject;
        }

        return this.handleRelationUpdates(className, object.objectId, object, relationUpdates).then(() => {
          return sanitizeDatabaseResult(originalObject, result.ops[0]);
        });
      });
    });
  }

  canAddField(schema, className, object, aclGroup, runOptions) {
    const classSchema = schema.schemaData[className];

    if (!classSchema) {
      return Promise.resolve();
    }

    const fields = Object.keys(object);
    const schemaFields = Object.keys(classSchema.fields);
    const newKeys = fields.filter(field => {
      // Skip fields that are unset
      if (object[field] && object[field].__op && object[field].__op === 'Delete') {
        return false;
      }

      return schemaFields.indexOf(field) < 0;
    });

    if (newKeys.length > 0) {
      // adds a marker that new field is being adding during update
      runOptions.addsField = true;
      const action = runOptions.action;
      return schema.validatePermission(className, aclGroup, 'addField', action);
    }

    return Promise.resolve();
  } // Won't delete collections in the system namespace

  /**
   * Delete all classes and clears the schema cache
   *
   * @param {boolean} fast set to true if it's ok to just delete rows and not indexes
   * @returns {Promise<void>} when the deletions completes
   */


  deleteEverything(fast = false) {
    this.schemaPromise = null;
    return Promise.all([this.adapter.deleteAllClasses(fast), this.schemaCache.clear()]);
  } // Returns a promise for a list of related ids given an owning id.
  // className here is the owning className.


  relatedIds(className, key, owningId, queryOptions) {
    const {
      skip,
      limit,
      sort
    } = queryOptions;
    const findOptions = {};

    if (sort && sort.createdAt && this.adapter.canSortOnJoinTables) {
      findOptions.sort = {
        _id: sort.createdAt
      };
      findOptions.limit = limit;
      findOptions.skip = skip;
      queryOptions.skip = 0;
    }

    return this.adapter.find(joinTableName(className, key), relationSchema, {
      owningId
    }, findOptions).then(results => results.map(result => result.relatedId));
  } // Returns a promise for a list of owning ids given some related ids.
  // className here is the owning className.


  owningIds(className, key, relatedIds) {
    return this.adapter.find(joinTableName(className, key), relationSchema, {
      relatedId: {
        $in: relatedIds
      }
    }, {}).then(results => results.map(result => result.owningId));
  } // Modifies query so that it no longer has $in on relation fields, or
  // equal-to-pointer constraints on relation fields.
  // Returns a promise that resolves when query is mutated


  reduceInRelation(className, query, schema) {
    // Search for an in-relation or equal-to-relation
    // Make it sequential for now, not sure of paralleization side effects
    if (query['$or']) {
      const ors = query['$or'];
      return Promise.all(ors.map((aQuery, index) => {
        return this.reduceInRelation(className, aQuery, schema).then(aQuery => {
          query['$or'][index] = aQuery;
        });
      })).then(() => {
        return Promise.resolve(query);
      });
    }

    const promises = Object.keys(query).map(key => {
      const t = schema.getExpectedType(className, key);

      if (!t || t.type !== 'Relation') {
        return Promise.resolve(query);
      }

      let queries = null;

      if (query[key] && (query[key]['$in'] || query[key]['$ne'] || query[key]['$nin'] || query[key].__type == 'Pointer')) {
        // Build the list of queries
        queries = Object.keys(query[key]).map(constraintKey => {
          let relatedIds;
          let isNegation = false;

          if (constraintKey === 'objectId') {
            relatedIds = [query[key].objectId];
          } else if (constraintKey == '$in') {
            relatedIds = query[key]['$in'].map(r => r.objectId);
          } else if (constraintKey == '$nin') {
            isNegation = true;
            relatedIds = query[key]['$nin'].map(r => r.objectId);
          } else if (constraintKey == '$ne') {
            isNegation = true;
            relatedIds = [query[key]['$ne'].objectId];
          } else {
            return;
          }

          return {
            isNegation,
            relatedIds
          };
        });
      } else {
        queries = [{
          isNegation: false,
          relatedIds: []
        }];
      } // remove the current queryKey as we don,t need it anymore


      delete query[key]; // execute each query independently to build the list of
      // $in / $nin

      const promises = queries.map(q => {
        if (!q) {
          return Promise.resolve();
        }

        return this.owningIds(className, key, q.relatedIds).then(ids => {
          if (q.isNegation) {
            this.addNotInObjectIdsIds(ids, query);
          } else {
            this.addInObjectIdsIds(ids, query);
          }

          return Promise.resolve();
        });
      });
      return Promise.all(promises).then(() => {
        return Promise.resolve();
      });
    });
    return Promise.all(promises).then(() => {
      return Promise.resolve(query);
    });
  } // Modifies query so that it no longer has $relatedTo
  // Returns a promise that resolves when query is mutated


  reduceRelationKeys(className, query, queryOptions) {
    if (query['$or']) {
      return Promise.all(query['$or'].map(aQuery => {
        return this.reduceRelationKeys(className, aQuery, queryOptions);
      }));
    }

    var relatedTo = query['$relatedTo'];

    if (relatedTo) {
      return this.relatedIds(relatedTo.object.className, relatedTo.key, relatedTo.object.objectId, queryOptions).then(ids => {
        delete query['$relatedTo'];
        this.addInObjectIdsIds(ids, query);
        return this.reduceRelationKeys(className, query, queryOptions);
      }).then(() => {});
    }
  }

  addInObjectIdsIds(ids = null, query) {
    const idsFromString = typeof query.objectId === 'string' ? [query.objectId] : null;
    const idsFromEq = query.objectId && query.objectId['$eq'] ? [query.objectId['$eq']] : null;
    const idsFromIn = query.objectId && query.objectId['$in'] ? query.objectId['$in'] : null; // -disable-next

    const allIds = [idsFromString, idsFromEq, idsFromIn, ids].filter(list => list !== null);
    const totalLength = allIds.reduce((memo, list) => memo + list.length, 0);
    let idsIntersection = [];

    if (totalLength > 125) {
      idsIntersection = _intersect.default.big(allIds);
    } else {
      idsIntersection = (0, _intersect.default)(allIds);
    } // Need to make sure we don't clobber existing shorthand $eq constraints on objectId.


    if (!('objectId' in query)) {
      query.objectId = {
        $in: undefined
      };
    } else if (typeof query.objectId === 'string') {
      query.objectId = {
        $in: undefined,
        $eq: query.objectId
      };
    }

    query.objectId['$in'] = idsIntersection;
    return query;
  }

  addNotInObjectIdsIds(ids = [], query) {
    const idsFromNin = query.objectId && query.objectId['$nin'] ? query.objectId['$nin'] : [];
    let allIds = [...idsFromNin, ...ids].filter(list => list !== null); // make a set and spread to remove duplicates

    allIds = [...new Set(allIds)]; // Need to make sure we don't clobber existing shorthand $eq constraints on objectId.

    if (!('objectId' in query)) {
      query.objectId = {
        $nin: undefined
      };
    } else if (typeof query.objectId === 'string') {
      query.objectId = {
        $nin: undefined,
        $eq: query.objectId
      };
    }

    query.objectId['$nin'] = allIds;
    return query;
  } // Runs a query on the database.
  // Returns a promise that resolves to a list of items.
  // Options:
  //   skip    number of results to skip.
  //   limit   limit to this number of results.
  //   sort    an object where keys are the fields to sort by.
  //           the value is +1 for ascending, -1 for descending.
  //   count   run a count instead of returning results.
  //   acl     restrict this operation with an ACL for the provided array
  //           of user objectIds and roles. acl: null means no user.
  //           when this field is not present, don't do anything regarding ACLs.
  //  caseInsensitive make string comparisons case insensitive
  // TODO: make userIds not needed here. The db adapter shouldn't know
  // anything about users, ideally. Then, improve the format of the ACL
  // arg to work like the others.


  find(className, query, {
    skip,
    limit,
    acl,
    sort = {},
    count,
    keys,
    op,
    distinct,
    pipeline,
    readPreference,
    hint,
    caseInsensitive = false,
    explain
  } = {}, auth = {}, validSchemaController) {
    const isMaster = acl === undefined;
    const aclGroup = acl || [];
    op = op || (typeof query.objectId == 'string' && Object.keys(query).length === 1 ? 'get' : 'find'); // Count operation if counting

    op = count === true ? 'count' : op;
    let classExists = true;
    return this.loadSchemaIfNeeded(validSchemaController).then(schemaController => {
      //Allow volatile classes if querying with Master (for _PushStatus)
      //TODO: Move volatile classes concept into mongo adapter, postgres adapter shouldn't care
      //that api.parse.com breaks when _PushStatus exists in mongo.
      return schemaController.getOneSchema(className, isMaster).catch(error => {
        // Behavior for non-existent classes is kinda weird on Parse.com. Probably doesn't matter too much.
        // For now, pretend the class exists but has no objects,
        if (error === undefined) {
          classExists = false;
          return {
            fields: {}
          };
        }

        throw error;
      }).then(schema => {
        // Parse.com treats queries on _created_at and _updated_at as if they were queries on createdAt and updatedAt,
        // so duplicate that behavior here. If both are specified, the correct behavior to match Parse.com is to
        // use the one that appears first in the sort list.
        if (sort._created_at) {
          sort.createdAt = sort._created_at;
          delete sort._created_at;
        }

        if (sort._updated_at) {
          sort.updatedAt = sort._updated_at;
          delete sort._updated_at;
        }

        const queryOptions = {
          skip,
          limit,
          sort,
          keys,
          readPreference,
          hint,
          caseInsensitive,
          explain
        };
        Object.keys(sort).forEach(fieldName => {
          if (fieldName.match(/^authData\.([a-zA-Z0-9_]+)\.id$/)) {
            throw new _node.Parse.Error(_node.Parse.Error.INVALID_KEY_NAME, `Cannot sort by ${fieldName}`);
          }

          const rootFieldName = getRootFieldName(fieldName);

          if (!SchemaController.fieldNameIsValid(rootFieldName)) {
            throw new _node.Parse.Error(_node.Parse.Error.INVALID_KEY_NAME, `Invalid field name: ${fieldName}.`);
          }
        });
        return (isMaster ? Promise.resolve() : schemaController.validatePermission(className, aclGroup, op)).then(() => this.reduceRelationKeys(className, query, queryOptions)).then(() => this.reduceInRelation(className, query, schemaController)).then(() => {
          let protectedFields;

          if (!isMaster) {
            query = this.addPointerPermissions(schemaController, className, op, query, aclGroup);
            /* Don't use projections to optimize the protectedFields since the protectedFields
            based on pointer-permissions are determined after querying. The filtering can
            overwrite the protected fields. */

            protectedFields = this.addProtectedFields(schemaController, className, query, aclGroup, auth);
          }

          if (!query) {
            if (op === 'get') {
              throw new _node.Parse.Error(_node.Parse.Error.OBJECT_NOT_FOUND, 'Object not found.');
            } else {
              return [];
            }
          }

          if (!isMaster) {
            if (op === 'update' || op === 'delete') {
              query = addWriteACL(query, aclGroup);
            } else {
              query = addReadACL(query, aclGroup);
            }
          }

          validateQuery(query, this.skipMongoDBServer13732Workaround);

          if (count) {
            if (!classExists) {
              return 0;
            } else {
              return this.adapter.count(className, schema, query, readPreference, undefined, hint);
            }
          } else if (distinct) {
            if (!classExists) {
              return [];
            } else {
              return this.adapter.distinct(className, schema, query, distinct);
            }
          } else if (pipeline) {
            if (!classExists) {
              return [];
            } else {
              return this.adapter.aggregate(className, schema, pipeline, readPreference, hint, explain);
            }
          } else if (explain) {
            return this.adapter.find(className, schema, query, queryOptions);
          } else {
            return this.adapter.find(className, schema, query, queryOptions).then(objects => objects.map(object => {
              object = untransformObjectACL(object);
              return filterSensitiveData(isMaster, aclGroup, auth, op, schemaController, className, protectedFields, object);
            })).catch(error => {
              throw new _node.Parse.Error(_node.Parse.Error.INTERNAL_SERVER_ERROR, error);
            });
          }
        });
      });
    });
  }

  deleteSchema(className) {
    return this.loadSchema({
      clearCache: true
    }).then(schemaController => schemaController.getOneSchema(className, true)).catch(error => {
      if (error === undefined) {
        return {
          fields: {}
        };
      } else {
        throw error;
      }
    }).then(schema => {
      return this.collectionExists(className).then(() => this.adapter.count(className, {
        fields: {}
      }, null, '', false)).then(count => {
        if (count > 0) {
          throw new _node.Parse.Error(255, `Class ${className} is not empty, contains ${count} objects, cannot drop schema.`);
        }

        return this.adapter.deleteClass(className);
      }).then(wasParseCollection => {
        if (wasParseCollection) {
          const relationFieldNames = Object.keys(schema.fields).filter(fieldName => schema.fields[fieldName].type === 'Relation');
          return Promise.all(relationFieldNames.map(name => this.adapter.deleteClass(joinTableName(className, name)))).then(() => {
            return;
          });
        } else {
          return Promise.resolve();
        }
      });
    });
  } // Constraints query using CLP's pointer permissions (PP) if any.
  // 1. Etract the user id from caller's ACLgroup;
  // 2. Exctract a list of field names that are PP for target collection and operation;
  // 3. Constraint the original query so that each PP field must
  // point to caller's id (or contain it in case of PP field being an array)


  addPointerPermissions(schema, className, operation, query, aclGroup = []) {
    // Check if class has public permission for operation
    // If the BaseCLP pass, let go through
    if (schema.testPermissionsForClassName(className, aclGroup, operation)) {
      return query;
    }

    const perms = schema.getClassLevelPermissions(className);
    const userACL = aclGroup.filter(acl => {
      return acl.indexOf('role:') != 0 && acl != '*';
    });
    const groupKey = ['get', 'find', 'count'].indexOf(operation) > -1 ? 'readUserFields' : 'writeUserFields';
    const permFields = [];

    if (perms[operation] && perms[operation].pointerFields) {
      permFields.push(...perms[operation].pointerFields);
    }

    if (perms[groupKey]) {
      for (const field of perms[groupKey]) {
        if (!permFields.includes(field)) {
          permFields.push(field);
        }
      }
    } // the ACL should have exactly 1 user


    if (permFields.length > 0) {
      // the ACL should have exactly 1 user
      // No user set return undefined
      // If the length is > 1, that means we didn't de-dupe users correctly
      if (userACL.length != 1) {
        return;
      }

      const userId = userACL[0];
      const userPointer = {
        __type: 'Pointer',
        className: '_User',
        objectId: userId
      };
      const ors = permFields.flatMap(key => {
        // constraint for single pointer setup
        const q = {
          [key]: userPointer
        }; // constraint for users-array setup

        const qa = {
          [key]: {
            $all: [userPointer]
          }
        }; // if we already have a constraint on the key, use the $and

        if (Object.prototype.hasOwnProperty.call(query, key)) {
          return [{
            $and: [q, query]
          }, {
            $and: [qa, query]
          }];
        } // otherwise just add the constaint


        return [Object.assign({}, query, q), Object.assign({}, query, qa)];
      });
      return {
        $or: ors
      };
    } else {
      return query;
    }
  }

  addProtectedFields(schema, className, query = {}, aclGroup = [], auth = {}) {
    const perms = schema.getClassLevelPermissions(className);
    if (!perms) return null;
    const protectedFields = perms.protectedFields;
    if (!protectedFields) return null;
    if (aclGroup.indexOf(query.objectId) > -1) return null; // remove userField keys since they are filtered after querying

    let protectedKeys = Object.keys(protectedFields).reduce((acc, val) => {
      if (val.startsWith('userField:')) return acc;
      return acc.concat(protectedFields[val]);
    }, []);
    [...(auth.userRoles || [])].forEach(role => {
      const fields = protectedFields[role];

      if (fields) {
        protectedKeys = protectedKeys.filter(v => fields.includes(v));
      }
    });
    return protectedKeys;
  }

  createTransactionalSession() {
    return this.adapter.createTransactionalSession().then(transactionalSession => {
      this._transactionalSession = transactionalSession;
    });
  }

  commitTransactionalSession() {
    if (!this._transactionalSession) {
      throw new Error('There is no transactional session to commit');
    }

    return this.adapter.commitTransactionalSession(this._transactionalSession).then(() => {
      this._transactionalSession = null;
    });
  }

  abortTransactionalSession() {
    if (!this._transactionalSession) {
      throw new Error('There is no transactional session to abort');
    }

    return this.adapter.abortTransactionalSession(this._transactionalSession).then(() => {
      this._transactionalSession = null;
    });
  } // TODO: create indexes on first creation of a _User object. Otherwise it's impossible to
  // have a Parse app without it having a _User collection.


  performInitialization() {
    const requiredUserFields = {
      fields: _objectSpread({}, SchemaController.defaultColumns._Default, {}, SchemaController.defaultColumns._User)
    };
    const requiredRoleFields = {
      fields: _objectSpread({}, SchemaController.defaultColumns._Default, {}, SchemaController.defaultColumns._Role)
    };
    const userClassPromise = this.loadSchema().then(schema => schema.enforceClassExists('_User'));
    const roleClassPromise = this.loadSchema().then(schema => schema.enforceClassExists('_Role'));
    const usernameUniqueness = userClassPromise.then(() => this.adapter.ensureUniqueness('_User', requiredUserFields, ['username'])).catch(error => {
      _logger.default.warn('Unable to ensure uniqueness for usernames: ', error);

      throw error;
    });
    const usernameCaseInsensitiveIndex = userClassPromise.then(() => this.adapter.ensureIndex('_User', requiredUserFields, ['username'], 'case_insensitive_username', true)).catch(error => {
      _logger.default.warn('Unable to create case insensitive username index: ', error);

      throw error;
    });
    const emailUniqueness = userClassPromise.then(() => this.adapter.ensureUniqueness('_User', requiredUserFields, ['email'])).catch(error => {
      _logger.default.warn('Unable to ensure uniqueness for user email addresses: ', error);

      throw error;
    });
    const emailCaseInsensitiveIndex = userClassPromise.then(() => this.adapter.ensureIndex('_User', requiredUserFields, ['email'], 'case_insensitive_email', true)).catch(error => {
      _logger.default.warn('Unable to create case insensitive email index: ', error);

      throw error;
    });
    const roleUniqueness = roleClassPromise.then(() => this.adapter.ensureUniqueness('_Role', requiredRoleFields, ['name'])).catch(error => {
      _logger.default.warn('Unable to ensure uniqueness for role name: ', error);

      throw error;
    });
    const indexPromise = this.adapter.updateSchemaWithIndexes(); // Create tables for volatile classes

    const adapterInit = this.adapter.performInitialization({
      VolatileClassesSchemas: SchemaController.VolatileClassesSchemas
    });
    return Promise.all([usernameUniqueness, usernameCaseInsensitiveIndex, emailUniqueness, emailCaseInsensitiveIndex, roleUniqueness, adapterInit, indexPromise]);
  }

}

module.exports = DatabaseController; // Expose validateQuery for tests

module.exports._validateQuery = validateQuery;
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbIi4uLy4uL3NyYy9Db250cm9sbGVycy9EYXRhYmFzZUNvbnRyb2xsZXIuanMiXSwibmFtZXMiOlsiYWRkV3JpdGVBQ0wiLCJxdWVyeSIsImFjbCIsIm5ld1F1ZXJ5IiwiXyIsImNsb25lRGVlcCIsIl93cGVybSIsIiRpbiIsImFkZFJlYWRBQ0wiLCJfcnBlcm0iLCJ0cmFuc2Zvcm1PYmplY3RBQ0wiLCJBQ0wiLCJyZXN1bHQiLCJlbnRyeSIsInJlYWQiLCJwdXNoIiwid3JpdGUiLCJzcGVjaWFsUXVlcnlrZXlzIiwiaXNTcGVjaWFsUXVlcnlLZXkiLCJrZXkiLCJpbmRleE9mIiwidmFsaWRhdGVRdWVyeSIsInNraXBNb25nb0RCU2VydmVyMTM3MzJXb3JrYXJvdW5kIiwiUGFyc2UiLCJFcnJvciIsIklOVkFMSURfUVVFUlkiLCIkb3IiLCJBcnJheSIsImZvckVhY2giLCJlbCIsIk9iamVjdCIsImtleXMiLCJub0NvbGxpc2lvbnMiLCJzb21lIiwic3VicSIsInByb3RvdHlwZSIsImhhc093blByb3BlcnR5IiwiY2FsbCIsImhhc05lYXJzIiwic3VicXVlcnkiLCIkYW5kIiwiJG5vciIsImxlbmd0aCIsIiRyZWdleCIsIiRvcHRpb25zIiwibWF0Y2giLCJJTlZBTElEX0tFWV9OQU1FIiwiZmlsdGVyU2Vuc2l0aXZlRGF0YSIsImlzTWFzdGVyIiwiYWNsR3JvdXAiLCJhdXRoIiwib3BlcmF0aW9uIiwic2NoZW1hIiwiY2xhc3NOYW1lIiwicHJvdGVjdGVkRmllbGRzIiwib2JqZWN0IiwidXNlcklkIiwidXNlciIsImlkIiwicGVybXMiLCJnZXRDbGFzc0xldmVsUGVybWlzc2lvbnMiLCJpc1JlYWRPcGVyYXRpb24iLCJwcm90ZWN0ZWRGaWVsZHNQb2ludGVyUGVybSIsImZpbHRlciIsInN0YXJ0c1dpdGgiLCJtYXAiLCJzdWJzdHJpbmciLCJ2YWx1ZSIsIm5ld1Byb3RlY3RlZEZpZWxkcyIsIm92ZXJyaWRlUHJvdGVjdGVkRmllbGRzIiwicG9pbnRlclBlcm0iLCJwb2ludGVyUGVybUluY2x1ZGVzVXNlciIsInJlYWRVc2VyRmllbGRWYWx1ZSIsImlzQXJyYXkiLCJvYmplY3RJZCIsImlzVXNlckNsYXNzIiwiayIsInBhc3N3b3JkIiwiX2hhc2hlZF9wYXNzd29yZCIsInNlc3Npb25Ub2tlbiIsIl9lbWFpbF92ZXJpZnlfdG9rZW4iLCJfcGVyaXNoYWJsZV90b2tlbiIsIl9wZXJpc2hhYmxlX3Rva2VuX2V4cGlyZXNfYXQiLCJfdG9tYnN0b25lIiwiX2VtYWlsX3ZlcmlmeV90b2tlbl9leHBpcmVzX2F0IiwiX2ZhaWxlZF9sb2dpbl9jb3VudCIsIl9hY2NvdW50X2xvY2tvdXRfZXhwaXJlc19hdCIsIl9wYXNzd29yZF9jaGFuZ2VkX2F0IiwiX3Bhc3N3b3JkX2hpc3RvcnkiLCJhdXRoRGF0YSIsInNwZWNpYWxLZXlzRm9yVXBkYXRlIiwiaXNTcGVjaWFsVXBkYXRlS2V5IiwiZXhwYW5kUmVzdWx0T25LZXlQYXRoIiwicGF0aCIsInNwbGl0IiwiZmlyc3RLZXkiLCJuZXh0UGF0aCIsInNsaWNlIiwiam9pbiIsInNhbml0aXplRGF0YWJhc2VSZXN1bHQiLCJvcmlnaW5hbE9iamVjdCIsInJlc3BvbnNlIiwiUHJvbWlzZSIsInJlc29sdmUiLCJrZXlVcGRhdGUiLCJfX29wIiwiam9pblRhYmxlTmFtZSIsImZsYXR0ZW5VcGRhdGVPcGVyYXRvcnNGb3JDcmVhdGUiLCJhbW91bnQiLCJJTlZBTElEX0pTT04iLCJvYmplY3RzIiwiQ09NTUFORF9VTkFWQUlMQUJMRSIsInRyYW5zZm9ybUF1dGhEYXRhIiwicHJvdmlkZXIiLCJwcm92aWRlckRhdGEiLCJmaWVsZE5hbWUiLCJmaWVsZHMiLCJ0eXBlIiwidW50cmFuc2Zvcm1PYmplY3RBQ0wiLCJvdXRwdXQiLCJnZXRSb290RmllbGROYW1lIiwicmVsYXRpb25TY2hlbWEiLCJyZWxhdGVkSWQiLCJvd25pbmdJZCIsIkRhdGFiYXNlQ29udHJvbGxlciIsImNvbnN0cnVjdG9yIiwiYWRhcHRlciIsInNjaGVtYUNhY2hlIiwic2NoZW1hUHJvbWlzZSIsIl90cmFuc2FjdGlvbmFsU2Vzc2lvbiIsImNvbGxlY3Rpb25FeGlzdHMiLCJjbGFzc0V4aXN0cyIsInB1cmdlQ29sbGVjdGlvbiIsImxvYWRTY2hlbWEiLCJ0aGVuIiwic2NoZW1hQ29udHJvbGxlciIsImdldE9uZVNjaGVtYSIsImRlbGV0ZU9iamVjdHNCeVF1ZXJ5IiwidmFsaWRhdGVDbGFzc05hbWUiLCJTY2hlbWFDb250cm9sbGVyIiwiY2xhc3NOYW1lSXNWYWxpZCIsInJlamVjdCIsIklOVkFMSURfQ0xBU1NfTkFNRSIsIm9wdGlvbnMiLCJjbGVhckNhY2hlIiwibG9hZCIsImxvYWRTY2hlbWFJZk5lZWRlZCIsInJlZGlyZWN0Q2xhc3NOYW1lRm9yS2V5IiwidCIsImdldEV4cGVjdGVkVHlwZSIsInRhcmdldENsYXNzIiwidmFsaWRhdGVPYmplY3QiLCJydW5PcHRpb25zIiwidW5kZWZpbmVkIiwicyIsImNhbkFkZEZpZWxkIiwidXBkYXRlIiwibWFueSIsInVwc2VydCIsImFkZHNGaWVsZCIsInNraXBTYW5pdGl6YXRpb24iLCJ2YWxpZGF0ZU9ubHkiLCJ2YWxpZFNjaGVtYUNvbnRyb2xsZXIiLCJvcmlnaW5hbFF1ZXJ5Iiwib3JpZ2luYWxVcGRhdGUiLCJyZWxhdGlvblVwZGF0ZXMiLCJ2YWxpZGF0ZVBlcm1pc3Npb24iLCJjb2xsZWN0UmVsYXRpb25VcGRhdGVzIiwiYWRkUG9pbnRlclBlcm1pc3Npb25zIiwiY2F0Y2giLCJlcnJvciIsInJvb3RGaWVsZE5hbWUiLCJmaWVsZE5hbWVJc1ZhbGlkIiwidXBkYXRlT3BlcmF0aW9uIiwiaW5uZXJLZXkiLCJpbmNsdWRlcyIsIklOVkFMSURfTkVTVEVEX0tFWSIsInVwZGF0ZU9iamVjdHNCeVF1ZXJ5IiwidXBzZXJ0T25lT2JqZWN0IiwiZmluZE9uZUFuZFVwZGF0ZSIsIk9CSkVDVF9OT1RfRk9VTkQiLCJoYW5kbGVSZWxhdGlvblVwZGF0ZXMiLCJvcHMiLCJkZWxldGVNZSIsInByb2Nlc3MiLCJvcCIsIngiLCJwZW5kaW5nIiwiYWRkUmVsYXRpb24iLCJyZW1vdmVSZWxhdGlvbiIsImFsbCIsImZyb21DbGFzc05hbWUiLCJmcm9tSWQiLCJ0b0lkIiwiZG9jIiwiY29kZSIsImRlc3Ryb3kiLCJwYXJzZUZvcm1hdFNjaGVtYSIsImNyZWF0ZSIsImNyZWF0ZWRBdCIsImlzbyIsIl9fdHlwZSIsInVwZGF0ZWRBdCIsImVuZm9yY2VDbGFzc0V4aXN0cyIsImNyZWF0ZU9iamVjdCIsImNvbnZlcnRTY2hlbWFUb0FkYXB0ZXJTY2hlbWEiLCJjbGFzc1NjaGVtYSIsInNjaGVtYURhdGEiLCJzY2hlbWFGaWVsZHMiLCJuZXdLZXlzIiwiZmllbGQiLCJhY3Rpb24iLCJkZWxldGVFdmVyeXRoaW5nIiwiZmFzdCIsImRlbGV0ZUFsbENsYXNzZXMiLCJjbGVhciIsInJlbGF0ZWRJZHMiLCJxdWVyeU9wdGlvbnMiLCJza2lwIiwibGltaXQiLCJzb3J0IiwiZmluZE9wdGlvbnMiLCJjYW5Tb3J0T25Kb2luVGFibGVzIiwiX2lkIiwiZmluZCIsInJlc3VsdHMiLCJvd25pbmdJZHMiLCJyZWR1Y2VJblJlbGF0aW9uIiwib3JzIiwiYVF1ZXJ5IiwiaW5kZXgiLCJwcm9taXNlcyIsInF1ZXJpZXMiLCJjb25zdHJhaW50S2V5IiwiaXNOZWdhdGlvbiIsInIiLCJxIiwiaWRzIiwiYWRkTm90SW5PYmplY3RJZHNJZHMiLCJhZGRJbk9iamVjdElkc0lkcyIsInJlZHVjZVJlbGF0aW9uS2V5cyIsInJlbGF0ZWRUbyIsImlkc0Zyb21TdHJpbmciLCJpZHNGcm9tRXEiLCJpZHNGcm9tSW4iLCJhbGxJZHMiLCJsaXN0IiwidG90YWxMZW5ndGgiLCJyZWR1Y2UiLCJtZW1vIiwiaWRzSW50ZXJzZWN0aW9uIiwiaW50ZXJzZWN0IiwiYmlnIiwiJGVxIiwiaWRzRnJvbU5pbiIsIlNldCIsIiRuaW4iLCJjb3VudCIsImRpc3RpbmN0IiwicGlwZWxpbmUiLCJyZWFkUHJlZmVyZW5jZSIsImhpbnQiLCJjYXNlSW5zZW5zaXRpdmUiLCJleHBsYWluIiwiX2NyZWF0ZWRfYXQiLCJfdXBkYXRlZF9hdCIsImFkZFByb3RlY3RlZEZpZWxkcyIsImFnZ3JlZ2F0ZSIsIklOVEVSTkFMX1NFUlZFUl9FUlJPUiIsImRlbGV0ZVNjaGVtYSIsImRlbGV0ZUNsYXNzIiwid2FzUGFyc2VDb2xsZWN0aW9uIiwicmVsYXRpb25GaWVsZE5hbWVzIiwibmFtZSIsInRlc3RQZXJtaXNzaW9uc0ZvckNsYXNzTmFtZSIsInVzZXJBQ0wiLCJncm91cEtleSIsInBlcm1GaWVsZHMiLCJwb2ludGVyRmllbGRzIiwidXNlclBvaW50ZXIiLCJmbGF0TWFwIiwicWEiLCIkYWxsIiwiYXNzaWduIiwicHJvdGVjdGVkS2V5cyIsImFjYyIsInZhbCIsImNvbmNhdCIsInVzZXJSb2xlcyIsInJvbGUiLCJ2IiwiY3JlYXRlVHJhbnNhY3Rpb25hbFNlc3Npb24iLCJ0cmFuc2FjdGlvbmFsU2Vzc2lvbiIsImNvbW1pdFRyYW5zYWN0aW9uYWxTZXNzaW9uIiwiYWJvcnRUcmFuc2FjdGlvbmFsU2Vzc2lvbiIsInBlcmZvcm1Jbml0aWFsaXphdGlvbiIsInJlcXVpcmVkVXNlckZpZWxkcyIsImRlZmF1bHRDb2x1bW5zIiwiX0RlZmF1bHQiLCJfVXNlciIsInJlcXVpcmVkUm9sZUZpZWxkcyIsIl9Sb2xlIiwidXNlckNsYXNzUHJvbWlzZSIsInJvbGVDbGFzc1Byb21pc2UiLCJ1c2VybmFtZVVuaXF1ZW5lc3MiLCJlbnN1cmVVbmlxdWVuZXNzIiwibG9nZ2VyIiwid2FybiIsInVzZXJuYW1lQ2FzZUluc2Vuc2l0aXZlSW5kZXgiLCJlbnN1cmVJbmRleCIsImVtYWlsVW5pcXVlbmVzcyIsImVtYWlsQ2FzZUluc2Vuc2l0aXZlSW5kZXgiLCJyb2xlVW5pcXVlbmVzcyIsImluZGV4UHJvbWlzZSIsInVwZGF0ZVNjaGVtYVdpdGhJbmRleGVzIiwiYWRhcHRlckluaXQiLCJWb2xhdGlsZUNsYXNzZXNTY2hlbWFzIiwibW9kdWxlIiwiZXhwb3J0cyIsIl92YWxpZGF0ZVF1ZXJ5Il0sIm1hcHBpbmdzIjoiOztBQUtBOztB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QUFQO0FBU0Q7O0FBN3lDc0I7O0FBa3pDekJJLE1BQU0sQ0FBQ0MsT0FBUCxHQUFpQmxNLGtCQUFqQixDLENBQ0E7O0FBQ0FpTSxNQUFNLENBQUNDLE9BQVAsQ0FBZUMsY0FBZixHQUFnQzFTLGFBQWhDIiwic291cmNlc0NvbnRlbnQiOlsi77u/Ly8gQGZsb3dcbi8vIEEgZGF0YWJhc2UgYWRhcHRlciB0aGF0IHdvcmtzIHdpdGggZGF0YSBleHBvcnRlZCBmcm9tIHRoZSBob3N0ZWRcbi8vIFBhcnNlIGRhdGFiYXNlLlxuXG4vLyBAZmxvdy1kaXNhYmxlLW5leHRcbmltcG9ydCB7IFBhcnNlIH0gZnJvbSAncGFyc2Uvbm9kZSc7XG4vLyBAZmxvdy1kaXNhYmxlLW5leHRcbmltcG9ydCBfIGZyb20gJ2xvZGFzaCc7XG4vLyBAZmxvdy1kaXNhYmxlLW5leHRcbmltcG9ydCBpbnRlcnNlY3QgZnJvbSAnaW50ZXJzZWN0Jztcbi8vIEBmbG93LWRpc2FibGUtbmV4dFxuaW1wb3J0IGRlZXBjb3B5IGZyb20gJ2RlZXBjb3B5JztcbmltcG9ydCBsb2dnZXIgZnJvbSAnLi4vbG9nZ2VyJztcbmltcG9ydCAqIGFzIFNjaGVtYUNvbnRyb2xsZXIgZnJvbSAnLi9TY2hlbWFDb250cm9sbGVyJztcbmltcG9ydCB7IFN0b3JhZ2VBZGFwdGVyIH0gZnJvbSAnLi4vQWRhcHRlcnMvU3RvcmFnZS9TdG9yYWdlQWRhcHRlcic7XG5pbXBvcnQgdHlwZSB7XG4gIFF1ZXJ5T3B0aW9ucyxcbiAgRnVsbFF1ZXJ5T3B0aW9ucyxcbn0gZnJvbSAnLi4vQWRhcHRlcnMvU3RvcmFnZS9TdG9yYWdlQWRhcHRlcic7XG5cbmZ1bmN0aW9uIGFkZFdyaXRlQUNMKHF1ZXJ5LCBhY2wpIHtcbiAgY29uc3QgbmV3UXVlcnkgPSBfLmNsb25lRGVlcChxdWVyeSk7XG4gIC8vQ2FuJ3QgYmUgYW55IGV4aXN0aW5nICdfd3Blcm0nIHF1ZXJ5LCB3ZSBkb24ndCBhbGxvdyBjbGllbnQgcXVlcmllcyBvbiB0aGF0LCBubyBuZWVkIHRvICRhbmRcbiAgbmV3UXVlcnkuX3dwZXJtID0geyAkaW46IFtudWxsLCAuLi5hY2xdIH07XG4gIHJldHVybiBuZXdRdWVyeTtcbn1cblxuZnVuY3Rpb24gYWRkUmVhZEFDTChxdWVyeSwgYWNsKSB7XG4gIGNvbnN0IG5ld1F1ZXJ5ID0gXy5jbG9uZURlZXAocXVlcnkpO1xuICAvL0Nhbid0IGJlIGFueSBleGlzdGluZyAnX3JwZXJtJyBxdWVyeSwgd2UgZG9uJ3QgYWxsb3cgY2xpZW50IHF1ZXJpZXMgb24gdGhhdCwgbm8gbmVlZCB0byAkYW5kXG4gIG5ld1F1ZXJ5Ll9ycGVybSA9IHsgJGluOiBbbnVsbCwgJyonLCAuLi5hY2xdIH07XG4gIHJldHVybiBuZXdRdWVyeTtcbn1cblxuLy8gVHJhbnNmb3JtcyBhIFJFU1QgQVBJIGZvcm1hdHRlZCBBQ0wgb2JqZWN0IHRvIG91ciB0d28tZmllbGQgbW9uZ28gZm9ybWF0LlxuY29uc3QgdHJhbnNmb3JtT2JqZWN0QUNMID0gKHsgQUNMLCAuLi5yZXN1bHQgfSkgPT4ge1xuICBpZiAoIUFDTCkge1xuICAgIHJldHVybiByZXN1bHQ7XG4gIH1cblxuICByZXN1bHQuX3dwZXJtID0gW107XG4gIHJlc3VsdC5fcnBlcm0gPSBbXTtcblxuICBmb3IgKGNvbnN0IGVudHJ5IGluIEFDTCkge1xuICAgIGlmIChBQ0xbZW50cnldLnJlYWQpIHtcbiAgICAgIHJlc3VsdC5fcnBlcm0ucHVzaChlbnRyeSk7XG4gICAgfVxuICAgIGlmIChBQ0xbZW50cnldLndyaXRlKSB7XG4gICAgICByZXN1bHQuX3dwZXJtLnB1c2goZW50cnkpO1xuICAgIH1cbiAgfVxuICByZXR1cm4gcmVzdWx0O1xufTtcblxuY29uc3Qgc3BlY2lhbFF1ZXJ5a2V5cyA9IFtcbiAgJyRhbmQnLFxuICAnJG9yJyxcbiAgJyRub3InLFxuICAnX3JwZXJtJyxcbiAgJ193cGVybScsXG4gICdfcGVyaXNoYWJsZV90b2tlbicsXG4gICdfZW1haWxfdmVyaWZ5X3Rva2VuJyxcbiAgJ19lbWFpbF92ZXJpZnlfdG9rZW5fZXhwaXJlc19hdCcsXG4gICdfYWNjb3VudF9sb2Nrb3V0X2V4cGlyZXNfYXQnLFxuICAnX2ZhaWxlZF9sb2dpbl9jb3VudCcsXG5dO1xuXG5jb25zdCBpc1NwZWNpYWxRdWVyeUtleSA9IGtleSA9PiB7XG4gIHJldHVybiBzcGVjaWFsUXVlcnlrZXlzLmluZGV4T2Yoa2V5KSA+PSAwO1xufTtcblxuY29uc3QgdmFsaWRhdGVRdWVyeSA9IChcbiAgcXVlcnk6IGFueSxcbiAgc2tpcE1vbmdvREJTZXJ2ZXIxMzczMldvcmthcm91bmQ6IGJvb2xlYW5cbik6IHZvaWQgPT4ge1xuICBpZiAocXVlcnkuQUNMKSB7XG4gICAgdGhyb3cgbmV3IFBhcnNlLkVycm9yKFBhcnNlLkVycm9yLklOVkFMSURfUVVFUlksICdDYW5ub3QgcXVlcnkgb24gQUNMLicpO1xuICB9XG5cbiAgaWYgKHF1ZXJ5LiRvcikge1xuICAgIGlmIChxdWVyeS4kb3IgaW5zdGFuY2VvZiBBcnJheSkge1xuICAgICAgcXVlcnkuJG9yLmZvckVhY2goZWwgPT5cbiAgICAgICAgdmFsaWRhdGVRdWVyeShlbCwgc2tpcE1vbmdvREJTZXJ2ZXIxMzczMldvcmthcm91bmQpXG4gICAgICApO1xuXG4gICAgICBpZiAoIXNraXBNb25nb0RCU2VydmVyMTM3MzJXb3JrYXJvdW5kKSB7XG4gICAgICAgIC8qIEluIE1vbmdvREIgMy4yICYgMy40LCAkb3IgcXVlcmllcyB3aGljaCBhcmUgbm90IGFsb25lIGF0IHRoZSB0b3BcbiAgICAgICAgICogbGV2ZWwgb2YgdGhlIHF1ZXJ5IGNhbiBub3QgbWFrZSBlZmZpY2llbnQgdXNlIG9mIGluZGV4ZXMgZHVlIHRvIGFcbiAgICAgICAgICogbG9uZyBzdGFuZGluZyBidWcga25vd24gYXMgU0VSVkVSLTEzNzMyLlxuICAgICAgICAgKlxuICAgICAgICAgKiBUaGlzIGJ1ZyB3YXMgZml4ZWQgaW4gTW9uZ29EQiB2ZXJzaW9uIDMuNi5cbiAgICAgICAgICpcbiAgICAgICAgICogRm9yIHZlcnNpb25zIHByZS0zLjYsIHRoZSBiZWxvdyBsb2dpYyBwcm9kdWNlcyBhIHN1YnN0YW50aWFsXG4gICAgICAgICAqIHBlcmZvcm1hbmNlIGltcHJvdmVtZW50IGluc2lkZSB0aGUgZGF0YWJhc2UgYnkgYXZvaWRpbmcgdGhlIGJ1Zy5cbiAgICAgICAgICpcbiAgICAgICAgICogRm9yIHZlcnNpb25zIDMuNiBhbmQgYWJvdmUsIHRoZXJlIGlzIG5vIHBlcmZvcm1hbmNlIGltcHJvdmVtZW50IGFuZFxuICAgICAgICAgKiB0aGUgbG9naWMgaXMgdW5uZWNlc3NhcnkuIFNvbWUgcXVlcnkgcGF0dGVybnMgYXJlIGV2ZW4gc2xvd2VkIGJ5XG4gICAgICAgICAqIHRoZSBiZWxvdyBsb2dpYywgZHVlIHRvIHRoZSBidWcgaGF2aW5nIGJlZW4gZml4ZWQgYW5kIGJldHRlclxuICAgICAgICAgKiBxdWVyeSBwbGFucyBiZWluZyBjaG9zZW4uXG4gICAgICAgICAqXG4gICAgICAgICAqIFdoZW4gdmVyc2lvbnMgYmVmb3JlIDMuNCBhcmUgbm8gbG9uZ2VyIHN1cHBvcnRlZCBieSB0aGlzIHByb2plY3QsXG4gICAgICAgICAqIHRoaXMgbG9naWMsIGFuZCB0aGUgYWNjb21wYW55aW5nIGBza2lwTW9uZ29EQlNlcnZlcjEzNzMyV29ya2Fyb3VuZGBcbiAgICAgICAgICogZmxhZywgY2FuIGJlIHJlbW92ZWQuXG4gICAgICAgICAqXG4gICAgICAgICAqIFRoaXMgYmxvY2sgcmVzdHJ1Y3R1cmVzIHF1ZXJpZXMgaW4gd2hpY2ggJG9yIGlzIG5vdCB0aGUgc29sZSB0b3BcbiAgICAgICAgICogbGV2ZWwgZWxlbWVudCBieSBtb3ZpbmcgYWxsIG90aGVyIHRvcC1sZXZlbCBwcmVkaWNhdGVzIGluc2lkZSBldmVyeVxuICAgICAgICAgKiBzdWJkb2N1bWVudCBvZiB0aGUgJG9yIHByZWRpY2F0ZSwgYWxsb3dpbmcgTW9uZ29EQidzIHF1ZXJ5IHBsYW5uZXJcbiAgICAgICAgICogdG8gbWFrZSBmdWxsIHVzZSBvZiB0aGUgbW9zdCByZWxldmFudCBpbmRleGVzLlxuICAgICAgICAgKlxuICAgICAgICAgKiBFRzogICAgICB7JG9yOiBbe2E6IDF9LCB7YTogMn1dLCBiOiAyfVxuICAgICAgICAgKiBCZWNvbWVzOiB7JG9yOiBbe2E6IDEsIGI6IDJ9LCB7YTogMiwgYjogMn1dfVxuICAgICAgICAgKlxuICAgICAgICAgKiBUaGUgb25seSBleGNlcHRpb25zIGFyZSAkbmVhciBhbmQgJG5lYXJTcGhlcmUgb3BlcmF0b3JzLCB3aGljaCBhcmVcbiAgICAgICAgICogY29uc3RyYWluZWQgdG8gb25seSAxIG9wZXJhdG9yIHBlciBxdWVyeS4gQXMgYSByZXN1bHQsIHRoZXNlIG9wc1xuICAgICAgICAgKiByZW1haW4gYXQgdGhlIHRvcCBsZXZlbFxuICAgICAgICAgKlxuICAgICAgICAgKiBodHRwczovL2ppcmEubW9uZ29kYi5vcmcvYnJvd3NlL1NFUlZFUi0xMzczMlxuICAgICAgICAgKiBodHRwczovL2dpdGh1Yi5jb20vcGFyc2UtY29tbXVuaXR5L3BhcnNlLXNlcnZlci9pc3N1ZXMvMzc2N1xuICAgICAgICAgKi9cbiAgICAgICAgT2JqZWN0LmtleXMocXVlcnkpLmZvckVhY2goa2V5ID0+IHtcbiAgICAgICAgICBjb25zdCBub0NvbGxpc2lvbnMgPSAhcXVlcnkuJG9yLnNvbWUoc3VicSA9PlxuICAgICAgICAgICAgT2JqZWN0LnByb3RvdHlwZS5oYXNPd25Qcm9wZXJ0eS5jYWxsKHN1YnEsIGtleSlcbiAgICAgICAgICApO1xuICAgICAgICAgIGxldCBoYXNOZWFycyA9IGZhbHNlO1xuICAgICAgICAgIGlmIChxdWVyeVtrZXldICE9IG51bGwgJiYgdHlwZW9mIHF1ZXJ5W2tleV0gPT0gJ29iamVjdCcpIHtcbiAgICAgICAgICAgIGhhc05lYXJzID0gJyRuZWFyJyBpbiBxdWVyeVtrZXldIHx8ICckbmVhclNwaGVyZScgaW4gcXVlcnlba2V5XTtcbiAgICAgICAgICB9XG4gICAgICAgICAgaWYgKGtleSAhPSAnJG9yJyAmJiBub0NvbGxpc2lvbnMgJiYgIWhhc05lYXJzKSB7XG4gICAgICAgICAgICBxdWVyeS4kb3IuZm9yRWFjaChzdWJxdWVyeSA9PiB7XG4gICAgICAgICAgICAgIHN1YnF1ZXJ5W2tleV0gPSBxdWVyeVtrZXldO1xuICAgICAgICAgICAgfSk7XG4gICAgICAgICAgICBkZWxldGUgcXVlcnlba2V5XTtcbiAgICAgICAgICB9XG4gICAgICAgIH0pO1xuICAgICAgICBxdWVyeS4kb3IuZm9yRWFjaChlbCA9PlxuICAgICAgICAgIHZhbGlkYXRlUXVlcnkoZWwsIHNraXBNb25nb0RCU2VydmVyMTM3MzJXb3JrYXJvdW5kKVxuICAgICAgICApO1xuICAgICAgfVxuICAgIH0gZWxzZSB7XG4gICAgICB0aHJvdyBuZXcgUGFyc2UuRXJyb3IoXG4gICAgICAgIFBhcnNlLkVycm9yLklOVkFMSURfUVVFUlksXG4gICAgICAgICdCYWQgJG9yIGZvcm1hdCAtIHVzZSBhbiBhcnJheSB2YWx1ZS4nXG4gICAgICApO1xuICAgIH1cbiAgfVxuXG4gIGlmIChxdWVyeS4kYW5kKSB7XG4gICAgaWYgKHF1ZXJ5LiRhbmQgaW5zdGFuY2VvZiBBcnJheSkge1xuICAgICAgcXVlcnkuJGFuZC5mb3JFYWNoKGVsID0+XG4gICAgICAgIHZhbGlkYXRlUXVlcnkoZWwsIHNraXBNb25nb0RCU2VydmVyMTM3MzJXb3JrYXJvdW5kKVxuICAgICAgKTtcbiAgICB9IGVsc2Uge1xuICAgICAgdGhyb3cgbmV3IFBhcnNlLkVycm9yKFxuICAgICAgICBQYXJzZS5FcnJvci5JTlZBTElEX1FVRVJZLFxuICAgICAgICAnQmFkICRhbmQgZm9ybWF0IC0gdXNlIGFuIGFycmF5IHZhbHVlLidcbiAgICAgICk7XG4gICAgfVxuICB9XG5cbiAgaWYgKHF1ZXJ5LiRub3IpIHtcbiAgICBpZiAocXVlcnkuJG5vciBpbnN0YW5jZW9mIEFycmF5ICYmIHF1ZXJ5LiRub3IubGVuZ3RoID4gMCkge1xuICAgICAgcXVlcnkuJG5vci5mb3JFYWNoKGVsID0+XG4gICAgICAgIHZhbGlkYXRlUXVlcnkoZWwsIHNraXBNb25nb0RCU2VydmVyMTM3MzJXb3JrYXJvdW5kKVxuICAgICAgKTtcbiAgICB9IGVsc2Uge1xuICAgICAgdGhyb3cgbmV3IFBhcnNlLkVycm9yKFxuICAgICAgICBQYXJzZS5FcnJvci5JTlZBTElEX1FVRVJZLFxuICAgICAgICAnQmFkICRub3IgZm9ybWF0IC0gdXNlIGFuIGFycmF5IG9mIGF0IGxlYXN0IDEgdmFsdWUuJ1xuICAgICAgKTtcbiAgICB9XG4gIH1cblxuICBPYmplY3Qua2V5cyhxdWVyeSkuZm9yRWFjaChrZXkgPT4ge1xuICAgIGlmIChxdWVyeSAmJiBxdWVyeVtrZXldICYmIHF1ZXJ5W2tleV0uJHJlZ2V4KSB7XG4gICAgICBpZiAodHlwZW9mIHF1ZXJ5W2tleV0uJG9wdGlvbnMgPT09ICdzdHJpbmcnKSB7XG4gICAgICAgIGlmICghcXVlcnlba2V5XS4kb3B0aW9ucy5tYXRjaCgvXltpbXhzXSskLykpIHtcbiAgICAgICAgICB0aHJvdyBuZXcgUGFyc2UuRXJyb3IoXG4gICAgICAgICAgICBQYXJzZS5FcnJvci5JTlZBTElEX1FVRVJZLFxuICAgICAgICAgICAgYEJhZCAkb3B0aW9ucyB2YWx1ZSBmb3IgcXVlcnk6ICR7cXVlcnlba2V5XS4kb3B0aW9uc31gXG4gICAgICAgICAgKTtcbiAgICAgICAgfVxuICAgICAgfVxuICAgIH1cbiAgICBpZiAoIWlzU3BlY2lhbFF1ZXJ5S2V5KGtleSkgJiYgIWtleS5tYXRjaCgvXlthLXpBLVpdW2EtekEtWjAtOV9cXC5dKiQvKSkge1xuICAgICAgdGhyb3cgbmV3IFBhcnNlLkVycm9yKFxuICAgICAgICBQYXJzZS5FcnJvci5JTlZBTElEX0tFWV9OQU1FLFxuICAgICAgICBgSW52YWxpZCBrZXkgbmFtZTogJHtrZXl9YFxuICAgICAgKTtcbiAgICB9XG4gIH0pO1xufTtcblxuLy8gRmlsdGVycyBvdXQgYW55IGRhdGEgdGhhdCBzaG91bGRuJ3QgYmUgb24gdGhpcyBSRVNULWZvcm1hdHRlZCBvYmplY3QuXG5jb25zdCBmaWx0ZXJTZW5zaXRpdmVEYXRhID0gKFxuICBpc01hc3RlcjogYm9vbGVhbixcbiAgYWNsR3JvdXA6IGFueVtdLFxuICBhdXRoOiBhbnksXG4gIG9wZXJhdGlvbjogYW55LFxuICBzY2hlbWE6IFNjaGVtYUNvbnRyb2xsZXIuU2NoZW1hQ29udHJvbGxlcixcbiAgY2xhc3NOYW1lOiBzdHJpbmcsXG4gIHByb3RlY3RlZEZpZWxkczogbnVsbCB8IEFycmF5PGFueT4sXG4gIG9iamVjdDogYW55XG4pID0+IHtcbiAgbGV0IHVzZXJJZCA9IG51bGw7XG4gIGlmIChhdXRoICYmIGF1dGgudXNlcikgdXNlcklkID0gYXV0aC51c2VyLmlkO1xuXG4gIC8vIHJlcGxhY2UgcHJvdGVjdGVkRmllbGRzIHdoZW4gdXNpbmcgcG9pbnRlci1wZXJtaXNzaW9uc1xuICBjb25zdCBwZXJtcyA9IHNjaGVtYS5nZXRDbGFzc0xldmVsUGVybWlzc2lvbnMoY2xhc3NOYW1lKTtcbiAgaWYgKHBlcm1zKSB7XG4gICAgY29uc3QgaXNSZWFkT3BlcmF0aW9uID0gWydnZXQnLCAnZmluZCddLmluZGV4T2Yob3BlcmF0aW9uKSA+IC0xO1xuXG4gICAgaWYgKGlzUmVhZE9wZXJhdGlvbiAmJiBwZXJtcy5wcm90ZWN0ZWRGaWVsZHMpIHtcbiAgICAgIC8vIGV4dHJhY3QgcHJvdGVjdGVkRmllbGRzIGFkZGVkIHdpdGggdGhlIHBvaW50ZXItcGVybWlzc2lvbiBwcmVmaXhcbiAgICAgIGNvbnN0IHByb3RlY3RlZEZpZWxkc1BvaW50ZXJQZXJtID0gT2JqZWN0LmtleXMocGVybXMucHJvdGVjdGVkRmllbGRzKVxuICAgICAgICAuZmlsdGVyKGtleSA9PiBrZXkuc3RhcnRzV2l0aCgndXNlckZpZWxkOicpKVxuICAgICAgICAubWFwKGtleSA9PiB7XG4gICAgICAgICAgcmV0dXJuIHsga2V5OiBrZXkuc3Vic3RyaW5nKDEwKSwgdmFsdWU6IHBlcm1zLnByb3RlY3RlZEZpZWxkc1trZXldIH07XG4gICAgICAgIH0pO1xuXG4gICAgICBjb25zdCBuZXdQcm90ZWN0ZWRGaWVsZHM6IEFycmF5PHN0cmluZz4gPSBbXTtcbiAgICAgIGxldCBvdmVycmlkZVByb3RlY3RlZEZpZWxkcyA9IGZhbHNlO1xuXG4gICAgICAvLyBjaGVjayBpZiB0aGUgb2JqZWN0IGdyYW50cyB0aGUgY3VycmVudCB1c2VyIGFjY2VzcyBiYXNlZCBvbiB0aGUgZXh0cmFjdGVkIGZpZWxkc1xuICAgICAgcHJvdGVjdGVkRmllbGRzUG9pbnRlclBlcm0uZm9yRWFjaChwb2ludGVyUGVybSA9PiB7XG4gICAgICAgIGxldCBwb2ludGVyUGVybUluY2x1ZGVzVXNlciA9IGZhbHNlO1xuICAgICAgICBjb25zdCByZWFkVXNlckZpZWxkVmFsdWUgPSBvYmplY3RbcG9pbnRlclBlcm0ua2V5XTtcbiAgICAgICAgaWYgKHJlYWRVc2VyRmllbGRWYWx1ZSkge1xuICAgICAgICAgIGlmIChBcnJheS5pc0FycmF5KHJlYWRVc2VyRmllbGRWYWx1ZSkpIHtcbiAgICAgICAgICAgIHBvaW50ZXJQZXJtSW5jbHVkZXNVc2VyID0gcmVhZFVzZXJGaWVsZFZhbHVlLnNvbWUoXG4gICAgICAgICAgICAgIHVzZXIgPT4gdXNlci5vYmplY3RJZCAmJiB1c2VyLm9iamVjdElkID09PSB1c2VySWRcbiAgICAgICAgICAgICk7XG4gICAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICAgIHBvaW50ZXJQZXJtSW5jbHVkZXNVc2VyID1cbiAgICAgICAgICAgICAgcmVhZFVzZXJGaWVsZFZhbHVlLm9iamVjdElkICYmXG4gICAgICAgICAgICAgIHJlYWRVc2VyRmllbGRWYWx1ZS5vYmplY3RJZCA9PT0gdXNlcklkO1xuICAgICAgICAgIH1cbiAgICAgICAgfVxuXG4gICAgICAgIGlmIChwb2ludGVyUGVybUluY2x1ZGVzVXNlcikge1xuICAgICAgICAgIG92ZXJyaWRlUHJvdGVjdGVkRmllbGRzID0gdHJ1ZTtcbiAgICAgICAgICBuZXdQcm90ZWN0ZWRGaWVsZHMucHVzaCguLi5wb2ludGVyUGVybS52YWx1ZSk7XG4gICAgICAgIH1cbiAgICAgIH0pO1xuXG4gICAgICAvLyBpZiBhdGxlYXN0IG9uZSBwb2ludGVyLXBlcm1pc3Npb24gYWZmZWN0ZWQgdGhlIGN1cnJlbnQgdXNlciBvdmVycmlkZSB0aGUgcHJvdGVjdGVkRmllbGRzXG4gICAgICBpZiAob3ZlcnJpZGVQcm90ZWN0ZWRGaWVsZHMpIHByb3RlY3RlZEZpZWxkcyA9IG5ld1Byb3RlY3RlZEZpZWxkcztcbiAgICB9XG4gIH1cblxuICBjb25zdCBpc1VzZXJDbGFzcyA9IGNsYXNzTmFtZSA9PT0gJ19Vc2VyJztcblxuICAvKiBzcGVjaWFsIHRyZWF0IGZvciB0aGUgdXNlciBjbGFzczogZG9uJ3QgZmlsdGVyIHByb3RlY3RlZEZpZWxkcyBpZiBjdXJyZW50bHkgbG9nZ2VkaW4gdXNlciBpc1xuICB0aGUgcmV0cmlldmVkIHVzZXIgKi9cbiAgaWYgKCEoaXNVc2VyQ2xhc3MgJiYgdXNlcklkICYmIG9iamVjdC5vYmplY3RJZCA9PT0gdXNlcklkKSlcbiAgICBwcm90ZWN0ZWRGaWVsZHMgJiYgcHJvdGVjdGVkRmllbGRzLmZvckVhY2goayA9PiBkZWxldGUgb2JqZWN0W2tdKTtcblxuICBpZiAoIWlzVXNlckNsYXNzKSB7XG4gICAgcmV0dXJuIG9iamVjdDtcbiAgfVxuXG4gIG9iamVjdC5wYXNzd29yZCA9IG9iamVjdC5faGFzaGVkX3Bhc3N3b3JkO1xuICBkZWxldGUgb2JqZWN0Ll9oYXNoZWRfcGFzc3dvcmQ7XG5cbiAgZGVsZXRlIG9iamVjdC5zZXNzaW9uVG9rZW47XG5cbiAgaWYgKGlzTWFzdGVyKSB7XG4gICAgcmV0dXJuIG9iamVjdDtcbiAgfVxuICBkZWxldGUgb2JqZWN0Ll9lbWFpbF92ZXJpZnlfdG9rZW47XG4gIGRlbGV0ZSBvYmplY3QuX3BlcmlzaGFibGVfdG9rZW47XG4gIGRlbGV0ZSBvYmplY3QuX3BlcmlzaGFibGVfdG9rZW5fZXhwaXJlc19hdDtcbiAgZGVsZXRlIG9iamVjdC5fdG9tYnN0b25lO1xuICBkZWxldGUgb2JqZWN0Ll9lbWFpbF92ZXJpZnlfdG9rZW5fZXhwaXJlc19hdDtcbiAgZGVsZXRlIG9iamVjdC5fZmFpbGVkX2xvZ2luX2NvdW50O1xuICBkZWxldGUgb2JqZWN0Ll9hY2NvdW50X2xvY2tvdXRfZXhwaXJlc19hdDtcbiAgZGVsZXRlIG9iamVjdC5fcGFzc3dvcmRfY2hhbmdlZF9hdDtcbiAgZGVsZXRlIG9iamVjdC5fcGFzc3dvcmRfaGlzdG9yeTtcblxuICBpZiAoYWNsR3JvdXAuaW5kZXhPZihvYmplY3Qub2JqZWN0SWQpID4gLTEpIHtcbiAgICByZXR1cm4gb2JqZWN0O1xuICB9XG4gIGRlbGV0ZSBvYmplY3QuYXV0aERhdGE7XG4gIHJldHVybiBvYmplY3Q7XG59O1xuXG5pbXBvcnQgdHlwZSB7IExvYWRTY2hlbWFPcHRpb25zIH0gZnJvbSAnLi90eXBlcyc7XG5cbi8vIFJ1bnMgYW4gdXBkYXRlIG9uIHRoZSBkYXRhYmFzZS5cbi8vIFJldHVybnMgYSBwcm9taXNlIGZvciBhbiBvYmplY3Qgd2l0aCB0aGUgbmV3IHZhbHVlcyBmb3IgZmllbGRcbi8vIG1vZGlmaWNhdGlvbnMgdGhhdCBkb24ndCBrbm93IHRoZWlyIHJlc3VsdHMgYWhlYWQgb2YgdGltZSwgbGlrZVxuLy8gJ2luY3JlbWVudCcuXG4vLyBPcHRpb25zOlxuLy8gICBhY2w6ICBhIGxpc3Qgb2Ygc3RyaW5ncy4gSWYgdGhlIG9iamVjdCB0byBiZSB1cGRhdGVkIGhhcyBhbiBBQ0wsXG4vLyAgICAgICAgIG9uZSBvZiB0aGUgcHJvdmlkZWQgc3RyaW5ncyBtdXN0IHByb3ZpZGUgdGhlIGNhbGxlciB3aXRoXG4vLyAgICAgICAgIHdyaXRlIHBlcm1pc3Npb25zLlxuY29uc3Qgc3BlY2lhbEtleXNGb3JVcGRhdGUgPSBbXG4gICdfaGFzaGVkX3Bhc3N3b3JkJyxcbiAgJ19wZXJpc2hhYmxlX3Rva2VuJyxcbiAgJ19lbWFpbF92ZXJpZnlfdG9rZW4nLFxuICAnX2VtYWlsX3ZlcmlmeV90b2tlbl9leHBpcmVzX2F0JyxcbiAgJ19hY2NvdW50X2xvY2tvdXRfZXhwaXJlc19hdCcsXG4gICdfZmFpbGVkX2xvZ2luX2NvdW50JyxcbiAgJ19wZXJpc2hhYmxlX3Rva2VuX2V4cGlyZXNfYXQnLFxuICAnX3Bhc3N3b3JkX2NoYW5nZWRfYXQnLFxuICAnX3Bhc3N3b3JkX2hpc3RvcnknLFxuXTtcblxuY29uc3QgaXNTcGVjaWFsVXBkYXRlS2V5ID0ga2V5ID0+IHtcbiAgcmV0dXJuIHNwZWNpYWxLZXlzRm9yVXBkYXRlLmluZGV4T2Yoa2V5KSA+PSAwO1xufTtcblxuZnVuY3Rpb24gZXhwYW5kUmVzdWx0T25LZXlQYXRoKG9iamVjdCwga2V5LCB2YWx1ZSkge1xuICBpZiAoa2V5LmluZGV4T2YoJy4nKSA8IDApIHtcbiAgICBvYmplY3Rba2V5XSA9IHZhbHVlW2tleV07XG4gICAgcmV0dXJuIG9iamVjdDtcbiAgfVxuICBjb25zdCBwYXRoID0ga2V5LnNwbGl0KCcuJyk7XG4gIGNvbnN0IGZpcnN0S2V5ID0gcGF0aFswXTtcbiAgY29uc3QgbmV4dFBhdGggPSBwYXRoLnNsaWNlKDEpLmpvaW4oJy4nKTtcbiAgb2JqZWN0W2ZpcnN0S2V5XSA9IGV4cGFuZFJlc3VsdE9uS2V5UGF0aChcbiAgICBvYmplY3RbZmlyc3RLZXldIHx8IHt9LFxuICAgIG5leHRQYXRoLFxuICAgIHZhbHVlW2ZpcnN0S2V5XVxuICApO1xuICBkZWxldGUgb2JqZWN0W2tleV07XG4gIHJldHVybiBvYmplY3Q7XG59XG5cbmZ1bmN0aW9uIHNhbml0aXplRGF0YWJhc2VSZXN1bHQob3JpZ2luYWxPYmplY3QsIHJlc3VsdCk6IFByb21pc2U8YW55PiB7XG4gIGNvbnN0IHJlc3BvbnNlID0ge307XG4gIGlmICghcmVzdWx0KSB7XG4gICAgcmV0dXJuIFByb21pc2UucmVzb2x2ZShyZXNwb25zZSk7XG4gIH1cbiAgT2JqZWN0LmtleXMob3JpZ2luYWxPYmplY3QpLmZvckVhY2goa2V5ID0+IHtcbiAgICBjb25zdCBrZXlVcGRhdGUgPSBvcmlnaW5hbE9iamVjdFtrZXldO1xuICAgIC8vIGRldGVybWluZSBpZiB0aGF0IHdhcyBhbiBvcFxuICAgIGlmIChcbiAgICAgIGtleVVwZGF0ZSAmJlxuICAgICAgdHlwZW9mIGtleVVwZGF0ZSA9PT0gJ29iamVjdCcgJiZcbiAgICAgIGtleVVwZGF0ZS5fX29wICYmXG4gICAgICBbJ0FkZCcsICdBZGRVbmlxdWUnLCAnUmVtb3ZlJywgJ0luY3JlbWVudCddLmluZGV4T2Yoa2V5VXBkYXRlLl9fb3ApID4gLTFcbiAgICApIHtcbiAgICAgIC8vIG9ubHkgdmFsaWQgb3BzIHRoYXQgcHJvZHVjZSBhbiBhY3Rpb25hYmxlIHJlc3VsdFxuICAgICAgLy8gdGhlIG9wIG1heSBoYXZlIGhhcHBlbmQgb24gYSBrZXlwYXRoXG4gICAgICBleHBhbmRSZXN1bHRPbktleVBhdGgocmVzcG9uc2UsIGtleSwgcmVzdWx0KTtcbiAgICB9XG4gIH0pO1xuICByZXR1cm4gUHJvbWlzZS5yZXNvbHZlKHJlc3BvbnNlKTtcbn1cblxuZnVuY3Rpb24gam9pblRhYmxlTmFtZShjbGFzc05hbWUsIGtleSkge1xuICByZXR1cm4gYF9Kb2luOiR7a2V5fToke2NsYXNzTmFtZX1gO1xufVxuXG5jb25zdCBmbGF0dGVuVXBkYXRlT3BlcmF0b3JzRm9yQ3JlYXRlID0gb2JqZWN0ID0+IHtcbiAgZm9yIChjb25zdCBrZXkgaW4gb2JqZWN0KSB7XG4gICAgaWYgKG9iamVjdFtrZXldICYmIG9iamVjdFtrZXldLl9fb3ApIHtcbiAgICAgIHN3aXRjaCAob2JqZWN0W2tleV0uX19vcCkge1xuICAgICAgICBjYXNlICdJbmNyZW1lbnQnOlxuICAgICAgICAgIGlmICh0eXBlb2Ygb2JqZWN0W2tleV0uYW1vdW50ICE9PSAnbnVtYmVyJykge1xuICAgICAgICAgICAgdGhyb3cgbmV3IFBhcnNlLkVycm9yKFxuICAgICAgICAgICAgICBQYXJzZS5FcnJvci5JTlZBTElEX0pTT04sXG4gICAgICAgICAgICAgICdvYmplY3RzIHRvIGFkZCBtdXN0IGJlIGFuIGFycmF5J1xuICAgICAgICAgICAgKTtcbiAgICAgICAgICB9XG4gICAgICAgICAgb2JqZWN0W2tleV0gPSBvYmplY3Rba2V5XS5hbW91bnQ7XG4gICAgICAgICAgYnJlYWs7XG4gICAgICAgIGNhc2UgJ0FkZCc6XG4gICAgICAgICAgaWYgKCEob2JqZWN0W2tleV0ub2JqZWN0cyBpbnN0YW5jZW9mIEFycmF5KSkge1xuICAgICAgICAgICAgdGhyb3cgbmV3IFBhcnNlLkVycm9yKFxuICAgICAgICAgICAgICBQYXJzZS5FcnJvci5JTlZBTElEX0pTT04sXG4gICAgICAgICAgICAgICdvYmplY3RzIHRvIGFkZCBtdXN0IGJlIGFuIGFycmF5J1xuICAgICAgICAgICAgKTtcbiAgICAgICAgICB9XG4gICAgICAgICAgb2JqZWN0W2tleV0gPSBvYmplY3Rba2V5XS5vYmplY3RzO1xuICAgICAgICAgIGJyZWFrO1xuICAgICAgICBjYXNlICdBZGRVbmlxdWUnOlxuICAgICAgICAgIGlmICghKG9iamVjdFtrZXldLm9iamVjdHMgaW5zdGFuY2VvZiBBcnJheSkpIHtcbiAgICAgICAgICAgIHRocm93IG5ldyBQYXJzZS5FcnJvcihcbiAgICAgICAgICAgICAgUGFyc2UuRXJyb3IuSU5WQUxJRF9KU09OLFxuICAgICAgICAgICAgICAnb2JqZWN0cyB0byBhZGQgbXVzdCBiZSBhbiBhcnJheSdcbiAgICAgICAgICAgICk7XG4gICAgICAgICAgfVxuICAgICAgICAgIG9iamVjdFtrZXldID0gb2JqZWN0W2tleV0ub2JqZWN0cztcbiAgICAgICAgICBicmVhaztcbiAgICAgICAgY2FzZSAnUmVtb3ZlJzpcbiAgICAgICAgICBpZiAoIShvYmplY3Rba2V5XS5vYmplY3RzIGluc3RhbmNlb2YgQXJyYXkpKSB7XG4gICAgICAgICAgICB0aHJvdyBuZXcgUGFyc2UuRXJyb3IoXG4gICAgICAgICAgICAgIFBhcnNlLkVycm9yLklOVkFMSURfSlNPTixcbiAgICAgICAgICAgICAgJ29iamVjdHMgdG8gYWRkIG11c3QgYmUgYW4gYXJyYXknXG4gICAgICAgICAgICApO1xuICAgICAgICAgIH1cbiAgICAgICAgICBvYmplY3Rba2V5XSA9IFtdO1xuICAgICAgICAgIGJyZWFrO1xuICAgICAgICBjYXNlICdEZWxldGUnOlxuICAgICAgICAgIGRlbGV0ZSBvYmplY3Rba2V5XTtcbiAgICAgICAgICBicmVhaztcbiAgICAgICAgZGVmYXVsdDpcbiAgICAgICAgICB0aHJvdyBuZXcgUGFyc2UuRXJyb3IoXG4gICAgICAgICAgICBQYXJzZS5FcnJvci5DT01NQU5EX1VOQVZBSUxBQkxFLFxuICAgICAgICAgICAgYFRoZSAke29iamVjdFtrZXldLl9fb3B9IG9wZXJhdG9yIGlzIG5vdCBzdXBwb3J0ZWQgeWV0LmBcbiAgICAgICAgICApO1xuICAgICAgfVxuICAgIH1cbiAgfVxufTtcblxuY29uc3QgdHJhbnNmb3JtQXV0aERhdGEgPSAoY2xhc3NOYW1lLCBvYmplY3QsIHNjaGVtYSkgPT4ge1xuICBpZiAob2JqZWN0LmF1dGhEYXRhICYmIGNsYXNzTmFtZSA9PT0gJ19Vc2VyJykge1xuICAgIE9iamVjdC5rZXlzKG9iamVjdC5hdXRoRGF0YSkuZm9yRWFjaChwcm92aWRlciA9PiB7XG4gICAgICBjb25zdCBwcm92aWRlckRhdGEgPSBvYmplY3QuYXV0aERhdGFbcHJvdmlkZXJdO1xuICAgICAgY29uc3QgZmllbGROYW1lID0gYF9hdXRoX2RhdGFfJHtwcm92aWRlcn1gO1xuICAgICAgaWYgKHByb3ZpZGVyRGF0YSA9PSBudWxsKSB7XG4gICAgICAgIG9iamVjdFtmaWVsZE5hbWVdID0ge1xuICAgICAgICAgIF9fb3A6ICdEZWxldGUnLFxuICAgICAgICB9O1xuICAgICAgfSBlbHNlIHtcbiAgICAgICAgb2JqZWN0W2ZpZWxkTmFtZV0gPSBwcm92aWRlckRhdGE7XG4gICAgICAgIHNjaGVtYS5maWVsZHNbZmllbGROYW1lXSA9IHsgdHlwZTogJ09iamVjdCcgfTtcbiAgICAgIH1cbiAgICB9KTtcbiAgICBkZWxldGUgb2JqZWN0LmF1dGhEYXRhO1xuICB9XG59O1xuLy8gVHJhbnNmb3JtcyBhIERhdGFiYXNlIGZvcm1hdCBBQ0wgdG8gYSBSRVNUIEFQSSBmb3JtYXQgQUNMXG5jb25zdCB1bnRyYW5zZm9ybU9iamVjdEFDTCA9ICh7IF9ycGVybSwgX3dwZXJtLCAuLi5vdXRwdXQgfSkgPT4ge1xuICBpZiAoX3JwZXJtIHx8IF93cGVybSkge1xuICAgIG91dHB1dC5BQ0wgPSB7fTtcblxuICAgIChfcnBlcm0gfHwgW10pLmZvckVhY2goZW50cnkgPT4ge1xuICAgICAgaWYgKCFvdXRwdXQuQUNMW2VudHJ5XSkge1xuICAgICAgICBvdXRwdXQuQUNMW2VudHJ5XSA9IHsgcmVhZDogdHJ1ZSB9O1xuICAgICAgfSBlbHNlIHtcbiAgICAgICAgb3V0cHV0LkFDTFtlbnRyeV1bJ3JlYWQnXSA9IHRydWU7XG4gICAgICB9XG4gICAgfSk7XG5cbiAgICAoX3dwZXJtIHx8IFtdKS5mb3JFYWNoKGVudHJ5ID0+IHtcbiAgICAgIGlmICghb3V0cHV0LkFDTFtlbnRyeV0pIHtcbiAgICAgICAgb3V0cHV0LkFDTFtlbnRyeV0gPSB7IHdyaXRlOiB0cnVlIH07XG4gICAgICB9IGVsc2Uge1xuICAgICAgICBvdXRwdXQuQUNMW2VudHJ5XVsnd3JpdGUnXSA9IHRydWU7XG4gICAgICB9XG4gICAgfSk7XG4gIH1cbiAgcmV0dXJuIG91dHB1dDtcbn07XG5cbi8qKlxuICogV2hlbiBxdWVyeWluZywgdGhlIGZpZWxkTmFtZSBtYXkgYmUgY29tcG91bmQsIGV4dHJhY3QgdGhlIHJvb3QgZmllbGROYW1lXG4gKiAgICAgYHRlbXBlcmF0dXJlLmNlbHNpdXNgIGJlY29tZXMgYHRlbXBlcmF0dXJlYFxuICogQHBhcmFtIHtzdHJpbmd9IGZpZWxkTmFtZSB0aGF0IG1heSBiZSBhIGNvbXBvdW5kIGZpZWxkIG5hbWVcbiAqIEByZXR1cm5zIHtzdHJpbmd9IHRoZSByb290IG5hbWUgb2YgdGhlIGZpZWxkXG4gKi9cbmNvbnN0IGdldFJvb3RGaWVsZE5hbWUgPSAoZmllbGROYW1lOiBzdHJpbmcpOiBzdHJpbmcgPT4ge1xuICByZXR1cm4gZmllbGROYW1lLnNwbGl0KCcuJylbMF07XG59O1xuXG5jb25zdCByZWxhdGlvblNjaGVtYSA9IHtcbiAgZmllbGRzOiB7IHJlbGF0ZWRJZDogeyB0eXBlOiAnU3RyaW5nJyB9LCBvd25pbmdJZDogeyB0eXBlOiAnU3RyaW5nJyB9IH0sXG59O1xuXG5jbGFzcyBEYXRhYmFzZUNvbnRyb2xsZXIge1xuICBhZGFwdGVyOiBTdG9yYWdlQWRhcHRlcjtcbiAgc2NoZW1hQ2FjaGU6IGFueTtcbiAgc2NoZW1hUHJvbWlzZTogP1Byb21pc2U8U2NoZW1hQ29udHJvbGxlci5TY2hlbWFDb250cm9sbGVyPjtcbiAgc2tpcE1vbmdvREJTZXJ2ZXIxMzczMldvcmthcm91bmQ6IGJvb2xlYW47XG4gIF90cmFuc2FjdGlvbmFsU2Vzc2lvbjogP2FueTtcblxuICBjb25zdHJ1Y3RvcihcbiAgICBhZGFwdGVyOiBTdG9yYWdlQWRhcHRlcixcbiAgICBzY2hlbWFDYWNoZTogYW55LFxuICAgIHNraXBNb25nb0RCU2VydmVyMTM3MzJXb3JrYXJvdW5kOiBib29sZWFuXG4gICkge1xuICAgIHRoaXMuYWRhcHRlciA9IGFkYXB0ZXI7XG4gICAgdGhpcy5zY2hlbWFDYWNoZSA9IHNjaGVtYUNhY2hlO1xuICAgIC8vIFdlIGRvbid0IHdhbnQgYSBtdXRhYmxlIHRoaXMuc2NoZW1hLCBiZWNhdXNlIHRoZW4geW91IGNvdWxkIGhhdmVcbiAgICAvLyBvbmUgcmVxdWVzdCB0aGF0IHVzZXMgZGlmZmVyZW50IHNjaGVtYXMgZm9yIGRpZmZlcmVudCBwYXJ0cyBvZlxuICAgIC8vIGl0LiBJbnN0ZWFkLCB1c2UgbG9hZFNjaGVtYSB0byBnZXQgYSBzY2hlbWEuXG4gICAgdGhpcy5zY2hlbWFQcm9taXNlID0gbnVsbDtcbiAgICB0aGlzLnNraXBNb25nb0RCU2VydmVyMTM3MzJXb3JrYXJvdW5kID0gc2tpcE1vbmdvREJTZXJ2ZXIxMzczMldvcmthcm91bmQ7XG4gICAgdGhpcy5fdHJhbnNhY3Rpb25hbFNlc3Npb24gPSBudWxsO1xuICB9XG5cbiAgY29sbGVjdGlvbkV4aXN0cyhjbGFzc05hbWU6IHN0cmluZyk6IFByb21pc2U8Ym9vbGVhbj4ge1xuICAgIHJldHVybiB0aGlzLmFkYXB0ZXIuY2xhc3NFeGlzdHMoY2xhc3NOYW1lKTtcbiAgfVxuXG4gIHB1cmdlQ29sbGVjdGlvbihjbGFzc05hbWU6IHN0cmluZyk6IFByb21pc2U8dm9pZD4ge1xuICAgIHJldHVybiB0aGlzLmxvYWRTY2hlbWEoKVxuICAgICAgLnRoZW4oc2NoZW1hQ29udHJvbGxlciA9PiBzY2hlbWFDb250cm9sbGVyLmdldE9uZVNjaGVtYShjbGFzc05hbWUpKVxuICAgICAgLnRoZW4oc2NoZW1hID0+IHRoaXMuYWRhcHRlci5kZWxldGVPYmplY3RzQnlRdWVyeShjbGFzc05hbWUsIHNjaGVtYSwge30pKTtcbiAgfVxuXG4gIHZhbGlkYXRlQ2xhc3NOYW1lKGNsYXNzTmFtZTogc3RyaW5nKTogUHJvbWlzZTx2b2lkPiB7XG4gICAgaWYgKCFTY2hlbWFDb250cm9sbGVyLmNsYXNzTmFtZUlzVmFsaWQoY2xhc3NOYW1lKSkge1xuICAgICAgcmV0dXJuIFByb21pc2UucmVqZWN0KFxuICAgICAgICBuZXcgUGFyc2UuRXJyb3IoXG4gICAgICAgICAgUGFyc2UuRXJyb3IuSU5WQUxJRF9DTEFTU19OQU1FLFxuICAgICAgICAgICdpbnZhbGlkIGNsYXNzTmFtZTogJyArIGNsYXNzTmFtZVxuICAgICAgICApXG4gICAgICApO1xuICAgIH1cbiAgICByZXR1cm4gUHJvbWlzZS5yZXNvbHZlKCk7XG4gIH1cblxuICAvLyBSZXR1cm5zIGEgcHJvbWlzZSBmb3IgYSBzY2hlbWFDb250cm9sbGVyLlxuICBsb2FkU2NoZW1hKFxuICAgIG9wdGlvbnM6IExvYWRTY2hlbWFPcHRpb25zID0geyBjbGVhckNhY2hlOiBmYWxzZSB9XG4gICk6IFByb21pc2U8U2NoZW1hQ29udHJvbGxlci5TY2hlbWFDb250cm9sbGVyPiB7XG4gICAgaWYgKHRoaXMuc2NoZW1hUHJvbWlzZSAhPSBudWxsKSB7XG4gICAgICByZXR1cm4gdGhpcy5zY2hlbWFQcm9taXNlO1xuICAgIH1cbiAgICB0aGlzLnNjaGVtYVByb21pc2UgPSBTY2hlbWFDb250cm9sbGVyLmxvYWQoXG4gICAgICB0aGlzLmFkYXB0ZXIsXG4gICAgICB0aGlzLnNjaGVtYUNhY2hlLFxuICAgICAgb3B0aW9uc1xuICAgICk7XG4gICAgdGhpcy5zY2hlbWFQcm9taXNlLnRoZW4oXG4gICAgICAoKSA9PiBkZWxldGUgdGhpcy5zY2hlbWFQcm9taXNlLFxuICAgICAgKCkgPT4gZGVsZXRlIHRoaXMuc2NoZW1hUHJvbWlzZVxuICAgICk7XG4gICAgcmV0dXJuIHRoaXMubG9hZFNjaGVtYShvcHRpb25zKTtcbiAgfVxuXG4gIGxvYWRTY2hlbWFJZk5lZWRlZChcbiAgICBzY2hlbWFDb250cm9sbGVyOiBTY2hlbWFDb250cm9sbGVyLlNjaGVtYUNvbnRyb2xsZXIsXG4gICAgb3B0aW9uczogTG9hZFNjaGVtYU9wdGlvbnMgPSB7IGNsZWFyQ2FjaGU6IGZhbHNlIH1cbiAgKTogUHJvbWlzZTxTY2hlbWFDb250cm9sbGVyLlNjaGVtYUNvbnRyb2xsZXI+IHtcbiAgICByZXR1cm4gc2NoZW1hQ29udHJvbGxlclxuICAgICAgPyBQcm9taXNlLnJlc29sdmUoc2NoZW1hQ29udHJvbGxlcilcbiAgICAgIDogdGhpcy5sb2FkU2NoZW1hKG9wdGlvbnMpO1xuICB9XG5cbiAgLy8gUmV0dXJucyBhIHByb21pc2UgZm9yIHRoZSBjbGFzc25hbWUgdGhhdCBpcyByZWxhdGVkIHRvIHRoZSBnaXZlblxuICAvLyBjbGFzc25hbWUgdGhyb3VnaCB0aGUga2V5LlxuICAvLyBUT0RPOiBtYWtlIHRoaXMgbm90IGluIHRoZSBEYXRhYmFzZUNvbnRyb2xsZXIgaW50ZXJmYWNlXG4gIHJlZGlyZWN0Q2xhc3NOYW1lRm9yS2V5KGNsYXNzTmFtZTogc3RyaW5nLCBrZXk6IHN0cmluZyk6IFByb21pc2U8P3N0cmluZz4ge1xuICAgIHJldHVybiB0aGlzLmxvYWRTY2hlbWEoKS50aGVuKHNjaGVtYSA9PiB7XG4gICAgICB2YXIgdCA9IHNjaGVtYS5nZXRFeHBlY3RlZFR5cGUoY2xhc3NOYW1lLCBrZXkpO1xuICAgICAgaWYgKHQgIT0gbnVsbCAmJiB0eXBlb2YgdCAhPT0gJ3N0cmluZycgJiYgdC50eXBlID09PSAnUmVsYXRpb24nKSB7XG4gICAgICAgIHJldHVybiB0LnRhcmdldENsYXNzO1xuICAgICAgfVxuICAgICAgcmV0dXJuIGNsYXNzTmFtZTtcbiAgICB9KTtcbiAgfVxuXG4gIC8vIFVzZXMgdGhlIHNjaGVtYSB0byB2YWxpZGF0ZSB0aGUgb2JqZWN0IChSRVNUIEFQSSBmb3JtYXQpLlxuICAvLyBSZXR1cm5zIGEgcHJvbWlzZSB0aGF0IHJlc29sdmVzIHRvIHRoZSBuZXcgc2NoZW1hLlxuICAvLyBUaGlzIGRvZXMgbm90IHVwZGF0ZSB0aGlzLnNjaGVtYSwgYmVjYXVzZSBpbiBhIHNpdHVhdGlvbiBsaWtlIGFcbiAgLy8gYmF0Y2ggcmVxdWVzdCwgdGhhdCBjb3VsZCBjb25mdXNlIG90aGVyIHVzZXJzIG9mIHRoZSBzY2hlbWEuXG4gIHZhbGlkYXRlT2JqZWN0KFxuICAgIGNsYXNzTmFtZTogc3RyaW5nLFxuICAgIG9iamVjdDogYW55LFxuICAgIHF1ZXJ5OiBhbnksXG4gICAgcnVuT3B0aW9uczogUXVlcnlPcHRpb25zXG4gICk6IFByb21pc2U8Ym9vbGVhbj4ge1xuICAgIGxldCBzY2hlbWE7XG4gICAgY29uc3QgYWNsID0gcnVuT3B0aW9ucy5hY2w7XG4gICAgY29uc3QgaXNNYXN0ZXIgPSBhY2wgPT09IHVuZGVmaW5lZDtcbiAgICB2YXIgYWNsR3JvdXA6IHN0cmluZ1tdID0gYWNsIHx8IFtdO1xuICAgIHJldHVybiB0aGlzLmxvYWRTY2hlbWEoKVxuICAgICAgLnRoZW4ocyA9PiB7XG4gICAgICAgIHNjaGVtYSA9IHM7XG4gICAgICAgIGlmIChpc01hc3Rlcikge1xuICAgICAgICAgIHJldHVybiBQcm9taXNlLnJlc29sdmUoKTtcbiAgICAgICAgfVxuICAgICAgICByZXR1cm4gdGhpcy5jYW5BZGRGaWVsZChcbiAgICAgICAgICBzY2hlbWEsXG4gICAgICAgICAgY2xhc3NOYW1lLFxuICAgICAgICAgIG9iamVjdCxcbiAgICAgICAgICBhY2xHcm91cCxcbiAgICAgICAgICBydW5PcHRpb25zXG4gICAgICAgICk7XG4gICAgICB9KVxuICAgICAgLnRoZW4oKCkgPT4ge1xuICAgICAgICByZXR1cm4gc2NoZW1hLnZhbGlkYXRlT2JqZWN0KGNsYXNzTmFtZSwgb2JqZWN0LCBxdWVyeSk7XG4gICAgICB9KTtcbiAgfVxuXG4gIHVwZGF0ZShcbiAgICBjbGFzc05hbWU6IHN0cmluZyxcbiAgICBxdWVyeTogYW55LFxuICAgIHVwZGF0ZTogYW55LFxuICAgIHsgYWNsLCBtYW55LCB1cHNlcnQsIGFkZHNGaWVsZCB9OiBGdWxsUXVlcnlPcHRpb25zID0ge30sXG4gICAgc2tpcFNhbml0aXphdGlvbjogYm9vbGVhbiA9IGZhbHNlLFxuICAgIHZhbGlkYXRlT25seTogYm9vbGVhbiA9IGZhbHNlLFxuICAgIHZhbGlkU2NoZW1hQ29udHJvbGxlcjogU2NoZW1hQ29udHJvbGxlci5TY2hlbWFDb250cm9sbGVyXG4gICk6IFByb21pc2U8YW55PiB7XG4gICAgY29uc3Qgb3JpZ2luYWxRdWVyeSA9IHF1ZXJ5O1xuICAgIGNvbnN0IG9yaWdpbmFsVXBkYXRlID0gdXBkYXRlO1xuICAgIC8vIE1ha2UgYSBjb3B5IG9mIHRoZSBvYmplY3QsIHNvIHdlIGRvbid0IG11dGF0ZSB0aGUgaW5jb21pbmcgZGF0YS5cbiAgICB1cGRhdGUgPSBkZWVwY29weSh1cGRhdGUpO1xuICAgIHZhciByZWxhdGlvblVwZGF0ZXMgPSBbXTtcbiAgICB2YXIgaXNNYXN0ZXIgPSBhY2wgPT09IHVuZGVmaW5lZDtcbiAgICB2YXIgYWNsR3JvdXAgPSBhY2wgfHwgW107XG5cbiAgICByZXR1cm4gdGhpcy5sb2FkU2NoZW1hSWZOZWVkZWQodmFsaWRTY2hlbWFDb250cm9sbGVyKS50aGVuKFxuICAgICAgc2NoZW1hQ29udHJvbGxlciA9PiB7XG4gICAgICAgIHJldHVybiAoaXNNYXN0ZXJcbiAgICAgICAgICA/IFByb21pc2UucmVzb2x2ZSgpXG4gICAgICAgICAgOiBzY2hlbWFDb250cm9sbGVyLnZhbGlkYXRlUGVybWlzc2lvbihjbGFzc05hbWUsIGFjbEdyb3VwLCAndXBkYXRlJylcbiAgICAgICAgKVxuICAgICAgICAgIC50aGVuKCgpID0+IHtcbiAgICAgICAgICAgIHJlbGF0aW9uVXBkYXRlcyA9IHRoaXMuY29sbGVjdFJlbGF0aW9uVXBkYXRlcyhcbiAgICAgICAgICAgICAgY2xhc3NOYW1lLFxuICAgICAgICAgICAgICBvcmlnaW5hbFF1ZXJ5Lm9iamVjdElkLFxuICAgICAgICAgICAgICB1cGRhdGVcbiAgICAgICAgICAgICk7XG4gICAgICAgICAgICBpZiAoIWlzTWFzdGVyKSB7XG4gICAgICAgICAgICAgIHF1ZXJ5ID0gdGhpcy5hZGRQb2ludGVyUGVybWlzc2lvbnMoXG4gICAgICAgICAgICAgICAgc2NoZW1hQ29udHJvbGxlcixcbiAgICAgICAgICAgICAgICBjbGFzc05hbWUsXG4gICAgICAgICAgICAgICAgJ3VwZGF0ZScsXG4gICAgICAgICAgICAgICAgcXVlcnksXG4gICAgICAgICAgICAgICAgYWNsR3JvdXBcbiAgICAgICAgICAgICAgKTtcblxuICAgICAgICAgICAgICBpZiAoYWRkc0ZpZWxkKSB7XG4gICAgICAgICAgICAgICAgcXVlcnkgPSB7XG4gICAgICAgICAgICAgICAgICAkYW5kOiBbXG4gICAgICAgICAgICAgICAgICAgIHF1ZXJ5LFxuICAgICAgICAgICAgICAgICAgICB0aGlzLmFkZFBvaW50ZXJQZXJtaXNzaW9ucyhcbiAgICAgICAgICAgICAgICAgICAgICBzY2hlbWFDb250cm9sbGVyLFxuICAgICAgICAgICAgICAgICAgICAgIGNsYXNzTmFtZSxcbiAgICAgICAgICAgICAgICAgICAgICAnYWRkRmllbGQnLFxuICAgICAgICAgICAgICAgICAgICAgIHF1ZXJ5LFxuICAgICAgICAgICAgICAgICAgICAgIGFjbEdyb3VwXG4gICAgICAgICAgICAgICAgICAgICksXG4gICAgICAgICAgICAgICAgICBdLFxuICAgICAgICAgICAgICAgIH07XG4gICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIGlmICghcXVlcnkpIHtcbiAgICAgICAgICAgICAgcmV0dXJuIFByb21pc2UucmVzb2x2ZSgpO1xuICAgICAgICAgICAgfVxuICAgICAgICAgICAgaWYgKGFjbCkge1xuICAgICAgICAgICAgICBxdWVyeSA9IGFkZFdyaXRlQUNMKHF1ZXJ5LCBhY2wpO1xuICAgICAgICAgICAgfVxuICAgICAgICAgICAgdmFsaWRhdGVRdWVyeShxdWVyeSwgdGhpcy5za2lwTW9uZ29EQlNlcnZlcjEzNzMyV29ya2Fyb3VuZCk7XG4gICAgICAgICAgICByZXR1cm4gc2NoZW1hQ29udHJvbGxlclxuICAgICAgICAgICAgICAuZ2V0T25lU2NoZW1hKGNsYXNzTmFtZSwgdHJ1ZSlcbiAgICAgICAgICAgICAgLmNhdGNoKGVycm9yID0+IHtcbiAgICAgICAgICAgICAgICAvLyBJZiB0aGUgc2NoZW1hIGRvZXNuJ3QgZXhpc3QsIHByZXRlbmQgaXQgZXhpc3RzIHdpdGggbm8gZmllbGRzLiBUaGlzIGJlaGF2aW9yXG4gICAgICAgICAgICAgICAgLy8gd2lsbCBsaWtlbHkgbmVlZCByZXZpc2l0aW5nLlxuICAgICAgICAgICAgICAgIGlmIChlcnJvciA9PT0gdW5kZWZpbmVkKSB7XG4gICAgICAgICAgICAgICAgICByZXR1cm4geyBmaWVsZHM6IHt9IH07XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIHRocm93IGVycm9yO1xuICAgICAgICAgICAgICB9KVxuICAgICAgICAgICAgICAudGhlbihzY2hlbWEgPT4ge1xuICAgICAgICAgICAgICAgIE9iamVjdC5rZXlzKHVwZGF0ZSkuZm9yRWFjaChmaWVsZE5hbWUgPT4ge1xuICAgICAgICAgICAgICAgICAgaWYgKGZpZWxkTmFtZS5tYXRjaCgvXmF1dGhEYXRhXFwuKFthLXpBLVowLTlfXSspXFwuaWQkLykpIHtcbiAgICAgICAgICAgICAgICAgICAgdGhyb3cgbmV3IFBhcnNlLkVycm9yKFxuICAgICAgICAgICAgICAgICAgICAgIFBhcnNlLkVycm9yLklOVkFMSURfS0VZX05BTUUsXG4gICAgICAgICAgICAgICAgICAgICAgYEludmFsaWQgZmllbGQgbmFtZSBmb3IgdXBkYXRlOiAke2ZpZWxkTmFtZX1gXG4gICAgICAgICAgICAgICAgICAgICk7XG4gICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICBjb25zdCByb290RmllbGROYW1lID0gZ2V0Um9vdEZpZWxkTmFtZShmaWVsZE5hbWUpO1xuICAgICAgICAgICAgICAgICAgaWYgKFxuICAgICAgICAgICAgICAgICAgICAhU2NoZW1hQ29udHJvbGxlci5maWVsZE5hbWVJc1ZhbGlkKHJvb3RGaWVsZE5hbWUpICYmXG4gICAgICAgICAgICAgICAgICAgICFpc1NwZWNpYWxVcGRhdGVLZXkocm9vdEZpZWxkTmFtZSlcbiAgICAgICAgICAgICAgICAgICkge1xuICAgICAgICAgICAgICAgICAgICB0aHJvdyBuZXcgUGFyc2UuRXJyb3IoXG4gICAgICAgICAgICAgICAgICAgICAgUGFyc2UuRXJyb3IuSU5WQUxJRF9LRVlfTkFNRSxcbiAgICAgICAgICAgICAgICAgICAgICBgSW52YWxpZCBmaWVsZCBuYW1lIGZvciB1cGRhdGU6ICR7ZmllbGROYW1lfWBcbiAgICAgICAgICAgICAgICAgICAgKTtcbiAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICB9KTtcbiAgICAgICAgICAgICAgICBmb3IgKGNvbnN0IHVwZGF0ZU9wZXJhdGlvbiBpbiB1cGRhdGUpIHtcbiAgICAgICAgICAgICAgICAgIGlmIChcbiAgICAgICAgICAgICAgICAgICAgdXBkYXRlW3VwZGF0ZU9wZXJhdGlvbl0gJiZcbiAgICAgICAgICAgICAgICAgICAgdHlwZW9mIHVwZGF0ZVt1cGRhdGVPcGVyYXRpb25dID09PSAnb2JqZWN0JyAmJlxuICAgICAgICAgICAgICAgICAgICBPYmplY3Qua2V5cyh1cGRhdGVbdXBkYXRlT3BlcmF0aW9uXSkuc29tZShcbiAgICAgICAgICAgICAgICAgICAgICBpbm5lcktleSA9PlxuICAgICAgICAgICAgICAgICAgICAgICAgaW5uZXJLZXkuaW5jbHVkZXMoJyQnKSB8fCBpbm5lcktleS5pbmNsdWRlcygnLicpXG4gICAgICAgICAgICAgICAgICAgIClcbiAgICAgICAgICAgICAgICAgICkge1xuICAgICAgICAgICAgICAgICAgICB0aHJvdyBuZXcgUGFyc2UuRXJyb3IoXG4gICAgICAgICAgICAgICAgICAgICAgUGFyc2UuRXJyb3IuSU5WQUxJRF9ORVNURURfS0VZLFxuICAgICAgICAgICAgICAgICAgICAgIFwiTmVzdGVkIGtleXMgc2hvdWxkIG5vdCBjb250YWluIHRoZSAnJCcgb3IgJy4nIGNoYXJhY3RlcnNcIlxuICAgICAgICAgICAgICAgICAgICApO1xuICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICB1cGRhdGUgPSB0cmFuc2Zvcm1PYmplY3RBQ0wodXBkYXRlKTtcbiAgICAgICAgICAgICAgICB0cmFuc2Zvcm1BdXRoRGF0YShjbGFzc05hbWUsIHVwZGF0ZSwgc2NoZW1hKTtcbiAgICAgICAgICAgICAgICBpZiAodmFsaWRhdGVPbmx5KSB7XG4gICAgICAgICAgICAgICAgICByZXR1cm4ge307XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGlmIChtYW55KSB7XG4gICAgICAgICAgICAgICAgICByZXR1cm4gdGhpcy5hZGFwdGVyLnVwZGF0ZU9iamVjdHNCeVF1ZXJ5KFxuICAgICAgICAgICAgICAgICAgICBjbGFzc05hbWUsXG4gICAgICAgICAgICAgICAgICAgIHNjaGVtYSxcbiAgICAgICAgICAgICAgICAgICAgcXVlcnksXG4gICAgICAgICAgICAgICAgICAgIHVwZGF0ZSxcbiAgICAgICAgICAgICAgICAgICAgdGhpcy5fdHJhbnNhY3Rpb25hbFNlc3Npb25cbiAgICAgICAgICAgICAgICAgICk7XG4gICAgICAgICAgICAgICAgfSBlbHNlIGlmICh1cHNlcnQpIHtcbiAgICAgICAgICAgICAgICAgIHJldHVybiB0aGlzLmFkYXB0ZXIudXBzZXJ0T25lT2JqZWN0KFxuICAgICAgICAgICAgICAgICAgICBjbGFzc05hbWUsXG4gICAgICAgICAgICAgICAgICAgIHNjaGVtYSxcbiAgICAgICAgICAgICAgICAgICAgcXVlcnksXG4gICAgICAgICAgICAgICAgICAgIHVwZGF0ZSxcbiAgICAgICAgICAgICAgICAgICAgdGhpcy5fdHJhbnNhY3Rpb25hbFNlc3Npb25cbiAgICAgICAgICAgICAgICAgICk7XG4gICAgICAgICAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICAgICAgICAgIHJldHVybiB0aGlzLmFkYXB0ZXIuZmluZE9uZUFuZFVwZGF0ZShcbiAgICAgICAgICAgICAgICAgICAgY2xhc3NOYW1lLFxuICAgICAgICAgICAgICAgICAgICBzY2hlbWEsXG4gICAgICAgICAgICAgICAgICAgIHF1ZXJ5LFxuICAgICAgICAgICAgICAgICAgICB1cGRhdGUsXG4gICAgICAgICAgICAgICAgICAgIHRoaXMuX3RyYW5zYWN0aW9uYWxTZXNzaW9uXG4gICAgICAgICAgICAgICAgICApO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgfSk7XG4gICAgICAgICAgfSlcbiAgICAgICAgICAudGhlbigocmVzdWx0OiBhbnkpID0+IHtcbiAgICAgICAgICAgIGlmICghcmVzdWx0KSB7XG4gICAgICAgICAgICAgIHRocm93IG5ldyBQYXJzZS5FcnJvcihcbiAgICAgICAgICAgICAgICBQYXJzZS5FcnJvci5PQkpFQ1RfTk9UX0ZPVU5ELFxuICAgICAgICAgICAgICAgICdPYmplY3Qgbm90IGZvdW5kLidcbiAgICAgICAgICAgICAgKTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIGlmICh2YWxpZGF0ZU9ubHkpIHtcbiAgICAgICAgICAgICAgcmV0dXJuIHJlc3VsdDtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIHJldHVybiB0aGlzLmhhbmRsZVJlbGF0aW9uVXBkYXRlcyhcbiAgICAgICAgICAgICAgY2xhc3NOYW1lLFxuICAgICAgICAgICAgICBvcmlnaW5hbFF1ZXJ5Lm9iamVjdElkLFxuICAgICAgICAgICAgICB1cGRhdGUsXG4gICAgICAgICAgICAgIHJlbGF0aW9uVXBkYXRlc1xuICAgICAgICAgICAgKS50aGVuKCgpID0+IHtcbiAgICAgICAgICAgICAgcmV0dXJuIHJlc3VsdDtcbiAgICAgICAgICAgIH0pO1xuICAgICAgICAgIH0pXG4gICAgICAgICAgLnRoZW4ocmVzdWx0ID0+IHtcbiAgICAgICAgICAgIGlmIChza2lwU2FuaXRpemF0aW9uKSB7XG4gICAgICAgICAgICAgIHJldHVybiBQcm9taXNlLnJlc29sdmUocmVzdWx0KTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIHJldHVybiBzYW5pdGl6ZURhdGFiYXNlUmVzdWx0KG9yaWdpbmFsVXBkYXRlLCByZXN1bHQpO1xuICAgICAgICAgIH0pO1xuICAgICAgfVxuICAgICk7XG4gIH1cblxuICAvLyBDb2xsZWN0IGFsbCByZWxhdGlvbi11cGRhdGluZyBvcGVyYXRpb25zIGZyb20gYSBSRVNULWZvcm1hdCB1cGRhdGUuXG4gIC8vIFJldHVybnMgYSBsaXN0IG9mIGFsbCByZWxhdGlvbiB1cGRhdGVzIHRvIHBlcmZvcm1cbiAgLy8gVGhpcyBtdXRhdGVzIHVwZGF0ZS5cbiAgY29sbGVjdFJlbGF0aW9uVXBkYXRlcyhjbGFzc05hbWU6IHN0cmluZywgb2JqZWN0SWQ6ID9zdHJpbmcsIHVwZGF0ZTogYW55KSB7XG4gICAgdmFyIG9wcyA9IFtdO1xuICAgIHZhciBkZWxldGVNZSA9IFtdO1xuICAgIG9iamVjdElkID0gdXBkYXRlLm9iamVjdElkIHx8IG9iamVjdElkO1xuXG4gICAgdmFyIHByb2Nlc3MgPSAob3AsIGtleSkgPT4ge1xuICAgICAgaWYgKCFvcCkge1xuICAgICAgICByZXR1cm47XG4gICAgICB9XG4gICAgICBpZiAob3AuX19vcCA9PSAnQWRkUmVsYXRpb24nKSB7XG4gICAgICAgIG9wcy5wdXNoKHsga2V5LCBvcCB9KTtcbiAgICAgICAgZGVsZXRlTWUucHVzaChrZXkpO1xuICAgICAgfVxuXG4gICAgICBpZiAob3AuX19vcCA9PSAnUmVtb3ZlUmVsYXRpb24nKSB7XG4gICAgICAgIG9wcy5wdXNoKHsga2V5LCBvcCB9KTtcbiAgICAgICAgZGVsZXRlTWUucHVzaChrZXkpO1xuICAgICAgfVxuXG4gICAgICBpZiAob3AuX19vcCA9PSAnQmF0Y2gnKSB7XG4gICAgICAgIGZvciAodmFyIHggb2Ygb3Aub3BzKSB7XG4gICAgICAgICAgcHJvY2Vzcyh4LCBrZXkpO1xuICAgICAgICB9XG4gICAgICB9XG4gICAgfTtcblxuICAgIGZvciAoY29uc3Qga2V5IGluIHVwZGF0ZSkge1xuICAgICAgcHJvY2Vzcyh1cGRhdGVba2V5XSwga2V5KTtcbiAgICB9XG4gICAgZm9yIChjb25zdCBrZXkgb2YgZGVsZXRlTWUpIHtcbiAgICAgIGRlbGV0ZSB1cGRhdGVba2V5XTtcbiAgICB9XG4gICAgcmV0dXJuIG9wcztcbiAgfVxuXG4gIC8vIFByb2Nlc3NlcyByZWxhdGlvbi11cGRhdGluZyBvcGVyYXRpb25zIGZyb20gYSBSRVNULWZvcm1hdCB1cGRhdGUuXG4gIC8vIFJldHVybnMgYSBwcm9taXNlIHRoYXQgcmVzb2x2ZXMgd2hlbiBhbGwgdXBkYXRlcyBoYXZlIGJlZW4gcGVyZm9ybWVkXG4gIGhhbmRsZVJlbGF0aW9uVXBkYXRlcyhcbiAgICBjbGFzc05hbWU6IHN0cmluZyxcbiAgICBvYmplY3RJZDogc3RyaW5nLFxuICAgIHVwZGF0ZTogYW55LFxuICAgIG9wczogYW55XG4gICkge1xuICAgIHZhciBwZW5kaW5nID0gW107XG4gICAgb2JqZWN0SWQgPSB1cGRhdGUub2JqZWN0SWQgfHwgb2JqZWN0SWQ7XG4gICAgb3BzLmZvckVhY2goKHsga2V5LCBvcCB9KSA9PiB7XG4gICAgICBpZiAoIW9wKSB7XG4gICAgICAgIHJldHVybjtcbiAgICAgIH1cbiAgICAgIGlmIChvcC5fX29wID09ICdBZGRSZWxhdGlvbicpIHtcbiAgICAgICAgZm9yIChjb25zdCBvYmplY3Qgb2Ygb3Aub2JqZWN0cykge1xuICAgICAgICAgIHBlbmRpbmcucHVzaChcbiAgICAgICAgICAgIHRoaXMuYWRkUmVsYXRpb24oa2V5LCBjbGFzc05hbWUsIG9iamVjdElkLCBvYmplY3Qub2JqZWN0SWQpXG4gICAgICAgICAgKTtcbiAgICAgICAgfVxuICAgICAgfVxuXG4gICAgICBpZiAob3AuX19vcCA9PSAnUmVtb3ZlUmVsYXRpb24nKSB7XG4gICAgICAgIGZvciAoY29uc3Qgb2JqZWN0IG9mIG9wLm9iamVjdHMpIHtcbiAgICAgICAgICBwZW5kaW5nLnB1c2goXG4gICAgICAgICAgICB0aGlzLnJlbW92ZVJlbGF0aW9uKGtleSwgY2xhc3NOYW1lLCBvYmplY3RJZCwgb2JqZWN0Lm9iamVjdElkKVxuICAgICAgICAgICk7XG4gICAgICAgIH1cbiAgICAgIH1cbiAgICB9KTtcblxuICAgIHJldHVybiBQcm9taXNlLmFsbChwZW5kaW5nKTtcbiAgfVxuXG4gIC8vIEFkZHMgYSByZWxhdGlvbi5cbiAgLy8gUmV0dXJucyBhIHByb21pc2UgdGhhdCByZXNvbHZlcyBzdWNjZXNzZnVsbHkgaWZmIHRoZSBhZGQgd2FzIHN1Y2Nlc3NmdWwuXG4gIGFkZFJlbGF0aW9uKFxuICAgIGtleTogc3RyaW5nLFxuICAgIGZyb21DbGFzc05hbWU6IHN0cmluZyxcbiAgICBmcm9tSWQ6IHN0cmluZyxcbiAgICB0b0lkOiBzdHJpbmdcbiAgKSB7XG4gICAgY29uc3QgZG9jID0ge1xuICAgICAgcmVsYXRlZElkOiB0b0lkLFxuICAgICAgb3duaW5nSWQ6IGZyb21JZCxcbiAgICB9O1xuICAgIHJldHVybiB0aGlzLmFkYXB0ZXIudXBzZXJ0T25lT2JqZWN0KFxuICAgICAgYF9Kb2luOiR7a2V5fToke2Zyb21DbGFzc05hbWV9YCxcbiAgICAgIHJlbGF0aW9uU2NoZW1hLFxuICAgICAgZG9jLFxuICAgICAgZG9jLFxuICAgICAgdGhpcy5fdHJhbnNhY3Rpb25hbFNlc3Npb25cbiAgICApO1xuICB9XG5cbiAgLy8gUmVtb3ZlcyBhIHJlbGF0aW9uLlxuICAvLyBSZXR1cm5zIGEgcHJvbWlzZSB0aGF0IHJlc29sdmVzIHN1Y2Nlc3NmdWxseSBpZmYgdGhlIHJlbW92ZSB3YXNcbiAgLy8gc3VjY2Vzc2Z1bC5cbiAgcmVtb3ZlUmVsYXRpb24oXG4gICAga2V5OiBzdHJpbmcsXG4gICAgZnJvbUNsYXNzTmFtZTogc3RyaW5nLFxuICAgIGZyb21JZDogc3RyaW5nLFxuICAgIHRvSWQ6IHN0cmluZ1xuICApIHtcbiAgICB2YXIgZG9jID0ge1xuICAgICAgcmVsYXRlZElkOiB0b0lkLFxuICAgICAgb3duaW5nSWQ6IGZyb21JZCxcbiAgICB9O1xuICAgIHJldHVybiB0aGlzLmFkYXB0ZXJcbiAgICAgIC5kZWxldGVPYmplY3RzQnlRdWVyeShcbiAgICAgICAgYF9Kb2luOiR7a2V5fToke2Zyb21DbGFzc05hbWV9YCxcbiAgICAgICAgcmVsYXRpb25TY2hlbWEsXG4gICAgICAgIGRvYyxcbiAgICAgICAgdGhpcy5fdHJhbnNhY3Rpb25hbFNlc3Npb25cbiAgICAgIClcbiAgICAgIC5jYXRjaChlcnJvciA9PiB7XG4gICAgICAgIC8vIFdlIGRvbid0IGNhcmUgaWYgdGhleSB0cnkgdG8gZGVsZXRlIGEgbm9uLWV4aXN0ZW50IHJlbGF0aW9uLlxuICAgICAgICBpZiAoZXJyb3IuY29kZSA9PSBQYXJzZS5FcnJvci5PQkpFQ1RfTk9UX0ZPVU5EKSB7XG4gICAgICAgICAgcmV0dXJuO1xuICAgICAgICB9XG4gICAgICAgIHRocm93IGVycm9yO1xuICAgICAgfSk7XG4gIH1cblxuICAvLyBSZW1vdmVzIG9iamVjdHMgbWF0Y2hlcyB0aGlzIHF1ZXJ5IGZyb20gdGhlIGRhdGFiYXNlLlxuICAvLyBSZXR1cm5zIGEgcHJvbWlzZSB0aGF0IHJlc29sdmVzIHN1Y2Nlc3NmdWxseSBpZmYgdGhlIG9iamVjdCB3YXNcbiAgLy8gZGVsZXRlZC5cbiAgLy8gT3B0aW9uczpcbiAgLy8gICBhY2w6ICBhIGxpc3Qgb2Ygc3RyaW5ncy4gSWYgdGhlIG9iamVjdCB0byBiZSB1cGRhdGVkIGhhcyBhbiBBQ0wsXG4gIC8vICAgICAgICAgb25lIG9mIHRoZSBwcm92aWRlZCBzdHJpbmdzIG11c3QgcHJvdmlkZSB0aGUgY2FsbGVyIHdpdGhcbiAgLy8gICAgICAgICB3cml0ZSBwZXJtaXNzaW9ucy5cbiAgZGVzdHJveShcbiAgICBjbGFzc05hbWU6IHN0cmluZyxcbiAgICBxdWVyeTogYW55LFxuICAgIHsgYWNsIH06IFF1ZXJ5T3B0aW9ucyA9IHt9LFxuICAgIHZhbGlkU2NoZW1hQ29udHJvbGxlcjogU2NoZW1hQ29udHJvbGxlci5TY2hlbWFDb250cm9sbGVyXG4gICk6IFByb21pc2U8YW55PiB7XG4gICAgY29uc3QgaXNNYXN0ZXIgPSBhY2wgPT09IHVuZGVmaW5lZDtcbiAgICBjb25zdCBhY2xHcm91cCA9IGFjbCB8fCBbXTtcblxuICAgIHJldHVybiB0aGlzLmxvYWRTY2hlbWFJZk5lZWRlZCh2YWxpZFNjaGVtYUNvbnRyb2xsZXIpLnRoZW4oXG4gICAgICBzY2hlbWFDb250cm9sbGVyID0+IHtcbiAgICAgICAgcmV0dXJuIChpc01hc3RlclxuICAgICAgICAgID8gUHJvbWlzZS5yZXNvbHZlKClcbiAgICAgICAgICA6IHNjaGVtYUNvbnRyb2xsZXIudmFsaWRhdGVQZXJtaXNzaW9uKGNsYXNzTmFtZSwgYWNsR3JvdXAsICdkZWxldGUnKVxuICAgICAgICApLnRoZW4oKCkgPT4ge1xuICAgICAgICAgIGlmICghaXNNYXN0ZXIpIHtcbiAgICAgICAgICAgIHF1ZXJ5ID0gdGhpcy5hZGRQb2ludGVyUGVybWlzc2lvbnMoXG4gICAgICAgICAgICAgIHNjaGVtYUNvbnRyb2xsZXIsXG4gICAgICAgICAgICAgIGNsYXNzTmFtZSxcbiAgICAgICAgICAgICAgJ2RlbGV0ZScsXG4gICAgICAgICAgICAgIHF1ZXJ5LFxuICAgICAgICAgICAgICBhY2xHcm91cFxuICAgICAgICAgICAgKTtcbiAgICAgICAgICAgIGlmICghcXVlcnkpIHtcbiAgICAgICAgICAgICAgdGhyb3cgbmV3IFBhcnNlLkVycm9yKFxuICAgICAgICAgICAgICAgIFBhcnNlLkVycm9yLk9CSkVDVF9OT1RfRk9VTkQsXG4gICAgICAgICAgICAgICAgJ09iamVjdCBub3QgZm91bmQuJ1xuICAgICAgICAgICAgICApO1xuICAgICAgICAgICAgfVxuICAgICAgICAgIH1cbiAgICAgICAgICAvLyBkZWxldGUgYnkgcXVlcnlcbiAgICAgICAgICBpZiAoYWNsKSB7XG4gICAgICAgICAgICBxdWVyeSA9IGFkZFdyaXRlQUNMKHF1ZXJ5LCBhY2wpO1xuICAgICAgICAgIH1cbiAgICAgICAgICB2YWxpZGF0ZVF1ZXJ5KHF1ZXJ5LCB0aGlzLnNraXBNb25nb0RCU2VydmVyMTM3MzJXb3JrYXJvdW5kKTtcbiAgICAgICAgICByZXR1cm4gc2NoZW1hQ29udHJvbGxlclxuICAgICAgICAgICAgLmdldE9uZVNjaGVtYShjbGFzc05hbWUpXG4gICAgICAgICAgICAuY2F0Y2goZXJyb3IgPT4ge1xuICAgICAgICAgICAgICAvLyBJZiB0aGUgc2NoZW1hIGRvZXNuJ3QgZXhpc3QsIHByZXRlbmQgaXQgZXhpc3RzIHdpdGggbm8gZmllbGRzLiBUaGlzIGJlaGF2aW9yXG4gICAgICAgICAgICAgIC8vIHdpbGwgbGlrZWx5IG5lZWQgcmV2aXNpdGluZy5cbiAgICAgICAgICAgICAgaWYgKGVycm9yID09PSB1bmRlZmluZWQpIHtcbiAgICAgICAgICAgICAgICByZXR1cm4geyBmaWVsZHM6IHt9IH07XG4gICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgdGhyb3cgZXJyb3I7XG4gICAgICAgICAgICB9KVxuICAgICAgICAgICAgLnRoZW4ocGFyc2VGb3JtYXRTY2hlbWEgPT5cbiAgICAgICAgICAgICAgdGhpcy5hZGFwdGVyLmRlbGV0ZU9iamVjdHNCeVF1ZXJ5KFxuICAgICAgICAgICAgICAgIGNsYXNzTmFtZSxcbiAgICAgICAgICAgICAgICBwYXJzZUZvcm1hdFNjaGVtYSxcbiAgICAgICAgICAgICAgICBxdWVyeSxcbiAgICAgICAgICAgICAgICB0aGlzLl90cmFuc2FjdGlvbmFsU2Vzc2lvblxuICAgICAgICAgICAgICApXG4gICAgICAgICAgICApXG4gICAgICAgICAgICAuY2F0Y2goZXJyb3IgPT4ge1xuICAgICAgICAgICAgICAvLyBXaGVuIGRlbGV0aW5nIHNlc3Npb25zIHdoaWxlIGNoYW5naW5nIHBhc3N3b3JkcywgZG9uJ3QgdGhyb3cgYW4gZXJyb3IgaWYgdGhleSBkb24ndCBoYXZlIGFueSBzZXNzaW9ucy5cbiAgICAgICAgICAgICAgaWYgKFxuICAgICAgICAgICAgICAgIGNsYXNzTmFtZSA9PT0gJ19TZXNzaW9uJyAmJlxuICAgICAgICAgICAgICAgIGVycm9yLmNvZGUgPT09IFBhcnNlLkVycm9yLk9CSkVDVF9OT1RfRk9VTkRcbiAgICAgICAgICAgICAgKSB7XG4gICAgICAgICAgICAgICAgcmV0dXJuIFByb21pc2UucmVzb2x2ZSh7fSk7XG4gICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgdGhyb3cgZXJyb3I7XG4gICAgICAgICAgICB9KTtcbiAgICAgICAgfSk7XG4gICAgICB9XG4gICAgKTtcbiAgfVxuXG4gIC8vIEluc2VydHMgYW4gb2JqZWN0IGludG8gdGhlIGRhdGFiYXNlLlxuICAvLyBSZXR1cm5zIGEgcHJvbWlzZSB0aGF0IHJlc29sdmVzIHN1Y2Nlc3NmdWxseSBpZmYgdGhlIG9iamVjdCBzYXZlZC5cbiAgY3JlYXRlKFxuICAgIGNsYXNzTmFtZTogc3RyaW5nLFxuICAgIG9iamVjdDogYW55LFxuICAgIHsgYWNsIH06IFF1ZXJ5T3B0aW9ucyA9IHt9LFxuICAgIHZhbGlkYXRlT25seTogYm9vbGVhbiA9IGZhbHNlLFxuICAgIHZhbGlkU2NoZW1hQ29udHJvbGxlcjogU2NoZW1hQ29udHJvbGxlci5TY2hlbWFDb250cm9sbGVyXG4gICk6IFByb21pc2U8YW55PiB7XG4gICAgLy8gTWFrZSBhIGNvcHkgb2YgdGhlIG9iamVjdCwgc28gd2UgZG9uJ3QgbXV0YXRlIHRoZSBpbmNvbWluZyBkYXRhLlxuICAgIGNvbnN0IG9yaWdpbmFsT2JqZWN0ID0gb2JqZWN0O1xuICAgIG9iamVjdCA9IHRyYW5zZm9ybU9iamVjdEFDTChvYmplY3QpO1xuXG4gICAgb2JqZWN0LmNyZWF0ZWRBdCA9IHsgaXNvOiBvYmplY3QuY3JlYXRlZEF0LCBfX3R5cGU6ICdEYXRlJyB9O1xuICAgIG9iamVjdC51cGRhdGVkQXQgPSB7IGlzbzogb2JqZWN0LnVwZGF0ZWRBdCwgX190eXBlOiAnRGF0ZScgfTtcblxuICAgIHZhciBpc01hc3RlciA9IGFjbCA9PT0gdW5kZWZpbmVkO1xuICAgIHZhciBhY2xHcm91cCA9IGFjbCB8fCBbXTtcbiAgICBjb25zdCByZWxhdGlvblVwZGF0ZXMgPSB0aGlzLmNvbGxlY3RSZWxhdGlvblVwZGF0ZXMoXG4gICAgICBjbGFzc05hbWUsXG4gICAgICBudWxsLFxuICAgICAgb2JqZWN0XG4gICAgKTtcblxuICAgIHJldHVybiB0aGlzLnZhbGlkYXRlQ2xhc3NOYW1lKGNsYXNzTmFtZSlcbiAgICAgIC50aGVuKCgpID0+IHRoaXMubG9hZFNjaGVtYUlmTmVlZGVkKHZhbGlkU2NoZW1hQ29udHJvbGxlcikpXG4gICAgICAudGhlbihzY2hlbWFDb250cm9sbGVyID0+IHtcbiAgICAgICAgcmV0dXJuIChpc01hc3RlclxuICAgICAgICAgID8gUHJvbWlzZS5yZXNvbHZlKClcbiAgICAgICAgICA6IHNjaGVtYUNvbnRyb2xsZXIudmFsaWRhdGVQZXJtaXNzaW9uKGNsYXNzTmFtZSwgYWNsR3JvdXAsICdjcmVhdGUnKVxuICAgICAgICApXG4gICAgICAgICAgLnRoZW4oKCkgPT4gc2NoZW1hQ29udHJvbGxlci5lbmZvcmNlQ2xhc3NFeGlzdHMoY2xhc3NOYW1lKSlcbiAgICAgICAgICAudGhlbigoKSA9PiBzY2hlbWFDb250cm9sbGVyLmdldE9uZVNjaGVtYShjbGFzc05hbWUsIHRydWUpKVxuICAgICAgICAgIC50aGVuKHNjaGVtYSA9PiB7XG4gICAgICAgICAgICB0cmFuc2Zvcm1BdXRoRGF0YShjbGFzc05hbWUsIG9iamVjdCwgc2NoZW1hKTtcbiAgICAgICAgICAgIGZsYXR0ZW5VcGRhdGVPcGVyYXRvcnNGb3JDcmVhdGUob2JqZWN0KTtcbiAgICAgICAgICAgIGlmICh2YWxpZGF0ZU9ubHkpIHtcbiAgICAgICAgICAgICAgcmV0dXJuIHt9O1xuICAgICAgICAgICAgfVxuICAgICAgICAgICAgcmV0dXJuIHRoaXMuYWRhcHRlci5jcmVhdGVPYmplY3QoXG4gICAgICAgICAgICAgIGNsYXNzTmFtZSxcbiAgICAgICAgICAgICAgU2NoZW1hQ29udHJvbGxlci5jb252ZXJ0U2NoZW1hVG9BZGFwdGVyU2NoZW1hKHNjaGVtYSksXG4gICAgICAgICAgICAgIG9iamVjdCxcbiAgICAgICAgICAgICAgdGhpcy5fdHJhbnNhY3Rpb25hbFNlc3Npb25cbiAgICAgICAgICAgICk7XG4gICAgICAgICAgfSlcbiAgICAgICAgICAudGhlbihyZXN1bHQgPT4ge1xuICAgICAgICAgICAgaWYgKHZhbGlkYXRlT25seSkge1xuICAgICAgICAgICAgICByZXR1cm4gb3JpZ2luYWxPYmplY3Q7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICByZXR1cm4gdGhpcy5oYW5kbGVSZWxhdGlvblVwZGF0ZXMoXG4gICAgICAgICAgICAgIGNsYXNzTmFtZSxcbiAgICAgICAgICAgICAgb2JqZWN0Lm9iamVjdElkLFxuICAgICAgICAgICAgICBvYmplY3QsXG4gICAgICAgICAgICAgIHJlbGF0aW9uVXBkYXRlc1xuICAgICAgICAgICAgKS50aGVuKCgpID0+IHtcbiAgICAgICAgICAgICAgcmV0dXJuIHNhbml0aXplRGF0YWJhc2VSZXN1bHQob3JpZ2luYWxPYmplY3QsIHJlc3VsdC5vcHNbMF0pO1xuICAgICAgICAgICAgfSk7XG4gICAgICAgICAgfSk7XG4gICAgICB9KTtcbiAgfVxuXG4gIGNhbkFkZEZpZWxkKFxuICAgIHNjaGVtYTogU2NoZW1hQ29udHJvbGxlci5TY2hlbWFDb250cm9sbGVyLFxuICAgIGNsYXNzTmFtZTogc3RyaW5nLFxuICAgIG9iamVjdDogYW55LFxuICAgIGFjbEdyb3VwOiBzdHJpbmdbXSxcbiAgICBydW5PcHRpb25zOiBRdWVyeU9wdGlvbnNcbiAgKTogUHJvbWlzZTx2b2lkPiB7XG4gICAgY29uc3QgY2xhc3NTY2hlbWEgPSBzY2hlbWEuc2NoZW1hRGF0YVtjbGFzc05hbWVdO1xuICAgIGlmICghY2xhc3NTY2hlbWEpIHtcbiAgICAgIHJldHVybiBQcm9taXNlLnJlc29sdmUoKTtcbiAgICB9XG4gICAgY29uc3QgZmllbGRzID0gT2JqZWN0LmtleXMob2JqZWN0KTtcbiAgICBjb25zdCBzY2hlbWFGaWVsZHMgPSBPYmplY3Qua2V5cyhjbGFzc1NjaGVtYS5maWVsZHMpO1xuICAgIGNvbnN0IG5ld0tleXMgPSBmaWVsZHMuZmlsdGVyKGZpZWxkID0+IHtcbiAgICAgIC8vIFNraXAgZmllbGRzIHRoYXQgYXJlIHVuc2V0XG4gICAgICBpZiAoXG4gICAgICAgIG9iamVjdFtmaWVsZF0gJiZcbiAgICAgICAgb2JqZWN0W2ZpZWxkXS5fX29wICYmXG4gICAgICAgIG9iamVjdFtmaWVsZF0uX19vcCA9PT0gJ0RlbGV0ZSdcbiAgICAgICkge1xuICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgICB9XG4gICAgICByZXR1cm4gc2NoZW1hRmllbGRzLmluZGV4T2YoZmllbGQpIDwgMDtcbiAgICB9KTtcbiAgICBpZiAobmV3S2V5cy5sZW5ndGggPiAwKSB7XG4gICAgICAvLyBhZGRzIGEgbWFya2VyIHRoYXQgbmV3IGZpZWxkIGlzIGJlaW5nIGFkZGluZyBkdXJpbmcgdXBkYXRlXG4gICAgICBydW5PcHRpb25zLmFkZHNGaWVsZCA9IHRydWU7XG5cbiAgICAgIGNvbnN0IGFjdGlvbiA9IHJ1bk9wdGlvbnMuYWN0aW9uO1xuICAgICAgcmV0dXJuIHNjaGVtYS52YWxpZGF0ZVBlcm1pc3Npb24oY2xhc3NOYW1lLCBhY2xHcm91cCwgJ2FkZEZpZWxkJywgYWN0aW9uKTtcbiAgICB9XG4gICAgcmV0dXJuIFByb21pc2UucmVzb2x2ZSgpO1xuICB9XG5cbiAgLy8gV29uJ3QgZGVsZXRlIGNvbGxlY3Rpb25zIGluIHRoZSBzeXN0ZW0gbmFtZXNwYWNlXG4gIC8qKlxuICAgKiBEZWxldGUgYWxsIGNsYXNzZXMgYW5kIGNsZWFycyB0aGUgc2NoZW1hIGNhY2hlXG4gICAqXG4gICAqIEBwYXJhbSB7Ym9vbGVhbn0gZmFzdCBzZXQgdG8gdHJ1ZSBpZiBpdCdzIG9rIHRvIGp1c3QgZGVsZXRlIHJvd3MgYW5kIG5vdCBpbmRleGVzXG4gICAqIEByZXR1cm5zIHtQcm9taXNlPHZvaWQ+fSB3aGVuIHRoZSBkZWxldGlvbnMgY29tcGxldGVzXG4gICAqL1xuICBkZWxldGVFdmVyeXRoaW5nKGZhc3Q6IGJvb2xlYW4gPSBmYWxzZSk6IFByb21pc2U8YW55PiB7XG4gICAgdGhpcy5zY2hlbWFQcm9taXNlID0gbnVsbDtcbiAgICByZXR1cm4gUHJvbWlzZS5hbGwoW1xuICAgICAgdGhpcy5hZGFwdGVyLmRlbGV0ZUFsbENsYXNzZXMoZmFzdCksXG4gICAgICB0aGlzLnNjaGVtYUNhY2hlLmNsZWFyKCksXG4gICAgXSk7XG4gIH1cblxuICAvLyBSZXR1cm5zIGEgcHJvbWlzZSBmb3IgYSBsaXN0IG9mIHJlbGF0ZWQgaWRzIGdpdmVuIGFuIG93bmluZyBpZC5cbiAgLy8gY2xhc3NOYW1lIGhlcmUgaXMgdGhlIG93bmluZyBjbGFzc05hbWUuXG4gIHJlbGF0ZWRJZHMoXG4gICAgY2xhc3NOYW1lOiBzdHJpbmcsXG4gICAga2V5OiBzdHJpbmcsXG4gICAgb3duaW5nSWQ6IHN0cmluZyxcbiAgICBxdWVyeU9wdGlvbnM6IFF1ZXJ5T3B0aW9uc1xuICApOiBQcm9taXNlPEFycmF5PHN0cmluZz4+IHtcbiAgICBjb25zdCB7IHNraXAsIGxpbWl0LCBzb3J0IH0gPSBxdWVyeU9wdGlvbnM7XG4gICAgY29uc3QgZmluZE9wdGlvbnMgPSB7fTtcbiAgICBpZiAoc29ydCAmJiBzb3J0LmNyZWF0ZWRBdCAmJiB0aGlzLmFkYXB0ZXIuY2FuU29ydE9uSm9pblRhYmxlcykge1xuICAgICAgZmluZE9wdGlvbnMuc29ydCA9IHsgX2lkOiBzb3J0LmNyZWF0ZWRBdCB9O1xuICAgICAgZmluZE9wdGlvbnMubGltaXQgPSBsaW1pdDtcbiAgICAgIGZpbmRPcHRpb25zLnNraXAgPSBza2lwO1xuICAgICAgcXVlcnlPcHRpb25zLnNraXAgPSAwO1xuICAgIH1cbiAgICByZXR1cm4gdGhpcy5hZGFwdGVyXG4gICAgICAuZmluZChcbiAgICAgICAgam9pblRhYmxlTmFtZShjbGFzc05hbWUsIGtleSksXG4gICAgICAgIHJlbGF0aW9uU2NoZW1hLFxuICAgICAgICB7IG93bmluZ0lkIH0sXG4gICAgICAgIGZpbmRPcHRpb25zXG4gICAgICApXG4gICAgICAudGhlbihyZXN1bHRzID0+IHJlc3VsdHMubWFwKHJlc3VsdCA9PiByZXN1bHQucmVsYXRlZElkKSk7XG4gIH1cblxuICAvLyBSZXR1cm5zIGEgcHJvbWlzZSBmb3IgYSBsaXN0IG9mIG93bmluZyBpZHMgZ2l2ZW4gc29tZSByZWxhdGVkIGlkcy5cbiAgLy8gY2xhc3NOYW1lIGhlcmUgaXMgdGhlIG93bmluZyBjbGFzc05hbWUuXG4gIG93bmluZ0lkcyhcbiAgICBjbGFzc05hbWU6IHN0cmluZyxcbiAgICBrZXk6IHN0cmluZyxcbiAgICByZWxhdGVkSWRzOiBzdHJpbmdbXVxuICApOiBQcm9taXNlPHN0cmluZ1tdPiB7XG4gICAgcmV0dXJuIHRoaXMuYWRhcHRlclxuICAgICAgLmZpbmQoXG4gICAgICAgIGpvaW5UYWJsZU5hbWUoY2xhc3NOYW1lLCBrZXkpLFxuICAgICAgICByZWxhdGlvblNjaGVtYSxcbiAgICAgICAgeyByZWxhdGVkSWQ6IHsgJGluOiByZWxhdGVkSWRzIH0gfSxcbiAgICAgICAge31cbiAgICAgIClcbiAgICAgIC50aGVuKHJlc3VsdHMgPT4gcmVzdWx0cy5tYXAocmVzdWx0ID0+IHJlc3VsdC5vd25pbmdJZCkpO1xuICB9XG5cbiAgLy8gTW9kaWZpZXMgcXVlcnkgc28gdGhhdCBpdCBubyBsb25nZXIgaGFzICRpbiBvbiByZWxhdGlvbiBmaWVsZHMsIG9yXG4gIC8vIGVxdWFsLXRvLXBvaW50ZXIgY29uc3RyYWludHMgb24gcmVsYXRpb24gZmllbGRzLlxuICAvLyBSZXR1cm5zIGEgcHJvbWlzZSB0aGF0IHJlc29sdmVzIHdoZW4gcXVlcnkgaXMgbXV0YXRlZFxuICByZWR1Y2VJblJlbGF0aW9uKGNsYXNzTmFtZTogc3RyaW5nLCBxdWVyeTogYW55LCBzY2hlbWE6IGFueSk6IFByb21pc2U8YW55PiB7XG4gICAgLy8gU2VhcmNoIGZvciBhbiBpbi1yZWxhdGlvbiBvciBlcXVhbC10by1yZWxhdGlvblxuICAgIC8vIE1ha2UgaXQgc2VxdWVudGlhbCBmb3Igbm93LCBub3Qgc3VyZSBvZiBwYXJhbGxlaXphdGlvbiBzaWRlIGVmZmVjdHNcbiAgICBpZiAocXVlcnlbJyRvciddKSB7XG4gICAgICBjb25zdCBvcnMgPSBxdWVyeVsnJG9yJ107XG4gICAgICByZXR1cm4gUHJvbWlzZS5hbGwoXG4gICAgICAgIG9ycy5tYXAoKGFRdWVyeSwgaW5kZXgpID0+IHtcbiAgICAgICAgICByZXR1cm4gdGhpcy5yZWR1Y2VJblJlbGF0aW9uKGNsYXNzTmFtZSwgYVF1ZXJ5LCBzY2hlbWEpLnRoZW4oXG4gICAgICAgICAgICBhUXVlcnkgPT4ge1xuICAgICAgICAgICAgICBxdWVyeVsnJG9yJ11baW5kZXhdID0gYVF1ZXJ5O1xuICAgICAgICAgICAgfVxuICAgICAgICAgICk7XG4gICAgICAgIH0pXG4gICAgICApLnRoZW4oKCkgPT4ge1xuICAgICAgICByZXR1cm4gUHJvbWlzZS5yZXNvbHZlKHF1ZXJ5KTtcbiAgICAgIH0pO1xuICAgIH1cblxuICAgIGNvbnN0IHByb21pc2VzID0gT2JqZWN0LmtleXMocXVlcnkpLm1hcChrZXkgPT4ge1xuICAgICAgY29uc3QgdCA9IHNjaGVtYS5nZXRFeHBlY3RlZFR5cGUoY2xhc3NOYW1lLCBrZXkpO1xuICAgICAgaWYgKCF0IHx8IHQudHlwZSAhPT0gJ1JlbGF0aW9uJykge1xuICAgICAgICByZXR1cm4gUHJvbWlzZS5yZXNvbHZlKHF1ZXJ5KTtcbiAgICAgIH1cbiAgICAgIGxldCBxdWVyaWVzOiA/KGFueVtdKSA9IG51bGw7XG4gICAgICBpZiAoXG4gICAgICAgIHF1ZXJ5W2tleV0gJiZcbiAgICAgICAgKHF1ZXJ5W2tleV1bJyRpbiddIHx8XG4gICAgICAgICAgcXVlcnlba2V5XVsnJG5lJ10gfHxcbiAgICAgICAgICBxdWVyeVtrZXldWyckbmluJ10gfHxcbiAgICAgICAgICBxdWVyeVtrZXldLl9fdHlwZSA9PSAnUG9pbnRlcicpXG4gICAgICApIHtcbiAgICAgICAgLy8gQnVpbGQgdGhlIGxpc3Qgb2YgcXVlcmllc1xuICAgICAgICBxdWVyaWVzID0gT2JqZWN0LmtleXMocXVlcnlba2V5XSkubWFwKGNvbnN0cmFpbnRLZXkgPT4ge1xuICAgICAgICAgIGxldCByZWxhdGVkSWRzO1xuICAgICAgICAgIGxldCBpc05lZ2F0aW9uID0gZmFsc2U7XG4gICAgICAgICAgaWYgKGNvbnN0cmFpbnRLZXkgPT09ICdvYmplY3RJZCcpIHtcbiAgICAgICAgICAgIHJlbGF0ZWRJZHMgPSBbcXVlcnlba2V5XS5vYmplY3RJZF07XG4gICAgICAgICAgfSBlbHNlIGlmIChjb25zdHJhaW50S2V5ID09ICckaW4nKSB7XG4gICAgICAgICAgICByZWxhdGVkSWRzID0gcXVlcnlba2V5XVsnJGluJ10ubWFwKHIgPT4gci5vYmplY3RJZCk7XG4gICAgICAgICAgfSBlbHNlIGlmIChjb25zdHJhaW50S2V5ID09ICckbmluJykge1xuICAgICAgICAgICAgaXNOZWdhdGlvbiA9IHRydWU7XG4gICAgICAgICAgICByZWxhdGVkSWRzID0gcXVlcnlba2V5XVsnJG5pbiddLm1hcChyID0+IHIub2JqZWN0SWQpO1xuICAgICAgICAgIH0gZWxzZSBpZiAoY29uc3RyYWludEtleSA9PSAnJG5lJykge1xuICAgICAgICAgICAgaXNOZWdhdGlvbiA9IHRydWU7XG4gICAgICAgICAgICByZWxhdGVkSWRzID0gW3F1ZXJ5W2tleV1bJyRuZSddLm9iamVjdElkXTtcbiAgICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgIH1cbiAgICAgICAgICByZXR1cm4ge1xuICAgICAgICAgICAgaXNOZWdhdGlvbixcbiAgICAgICAgICAgIHJlbGF0ZWRJZHMsXG4gICAgICAgICAgfTtcbiAgICAgICAgfSk7XG4gICAgICB9IGVsc2Uge1xuICAgICAgICBxdWVyaWVzID0gW3sgaXNOZWdhdGlvbjogZmFsc2UsIHJlbGF0ZWRJZHM6IFtdIH1dO1xuICAgICAgfVxuXG4gICAgICAvLyByZW1vdmUgdGhlIGN1cnJlbnQgcXVlcnlLZXkgYXMgd2UgZG9uLHQgbmVlZCBpdCBhbnltb3JlXG4gICAgICBkZWxldGUgcXVlcnlba2V5XTtcbiAgICAgIC8vIGV4ZWN1dGUgZWFjaCBxdWVyeSBpbmRlcGVuZGVudGx5IHRvIGJ1aWxkIHRoZSBsaXN0IG9mXG4gICAgICAvLyAkaW4gLyAkbmluXG4gICAgICBjb25zdCBwcm9taXNlcyA9IHF1ZXJpZXMubWFwKHEgPT4ge1xuICAgICAgICBpZiAoIXEpIHtcbiAgICAgICAgICByZXR1cm4gUHJvbWlzZS5yZXNvbHZlKCk7XG4gICAgICAgIH1cbiAgICAgICAgcmV0dXJuIHRoaXMub3duaW5nSWRzKGNsYXNzTmFtZSwga2V5LCBxLnJlbGF0ZWRJZHMpLnRoZW4oaWRzID0+IHtcbiAgICAgICAgICBpZiAocS5pc05lZ2F0aW9uKSB7XG4gICAgICAgICAgICB0aGlzLmFkZE5vdEluT2JqZWN0SWRzSWRzKGlkcywgcXVlcnkpO1xuICAgICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgICB0aGlzLmFkZEluT2JqZWN0SWRzSWRzKGlkcywgcXVlcnkpO1xuICAgICAgICAgIH1cbiAgICAgICAgICByZXR1cm4gUHJvbWlzZS5yZXNvbHZlKCk7XG4gICAgICAgIH0pO1xuICAgICAgfSk7XG5cbiAgICAgIHJldHVybiBQcm9taXNlLmFsbChwcm9taXNlcykudGhlbigoKSA9PiB7XG4gICAgICAgIHJldHVybiBQcm9taXNlLnJlc29sdmUoKTtcbiAgICAgIH0pO1xuICAgIH0pO1xuXG4gICAgcmV0dXJuIFByb21pc2UuYWxsKHByb21pc2VzKS50aGVuKCgpID0+IHtcbiAgICAgIHJldHVybiBQcm9taXNlLnJlc29sdmUocXVlcnkpO1xuICAgIH0pO1xuICB9XG5cbiAgLy8gTW9kaWZpZXMgcXVlcnkgc28gdGhhdCBpdCBubyBsb25nZXIgaGFzICRyZWxhdGVkVG9cbiAgLy8gUmV0dXJucyBhIHByb21pc2UgdGhhdCByZXNvbHZlcyB3aGVuIHF1ZXJ5IGlzIG11dGF0ZWRcbiAgcmVkdWNlUmVsYXRpb25LZXlzKFxuICAgIGNsYXNzTmFtZTogc3RyaW5nLFxuICAgIHF1ZXJ5OiBhbnksXG4gICAgcXVlcnlPcHRpb25zOiBhbnlcbiAgKTogP1Byb21pc2U8dm9pZD4ge1xuICAgIGlmIChxdWVyeVsnJG9yJ10pIHtcbiAgICAgIHJldHVybiBQcm9taXNlLmFsbChcbiAgICAgICAgcXVlcnlbJyRvciddLm1hcChhUXVlcnkgPT4ge1xuICAgICAgICAgIHJldHVybiB0aGlzLnJlZHVjZVJlbGF0aW9uS2V5cyhjbGFzc05hbWUsIGFRdWVyeSwgcXVlcnlPcHRpb25zKTtcbiAgICAgICAgfSlcbiAgICAgICk7XG4gICAgfVxuXG4gICAgdmFyIHJlbGF0ZWRUbyA9IHF1ZXJ5WyckcmVsYXRlZFRvJ107XG4gICAgaWYgKHJlbGF0ZWRUbykge1xuICAgICAgcmV0dXJuIHRoaXMucmVsYXRlZElkcyhcbiAgICAgICAgcmVsYXRlZFRvLm9iamVjdC5jbGFzc05hbWUsXG4gICAgICAgIHJlbGF0ZWRUby5rZXksXG4gICAgICAgIHJlbGF0ZWRUby5vYmplY3Qub2JqZWN0SWQsXG4gICAgICAgIHF1ZXJ5T3B0aW9uc1xuICAgICAgKVxuICAgICAgICAudGhlbihpZHMgPT4ge1xuICAgICAgICAgIGRlbGV0ZSBxdWVyeVsnJHJlbGF0ZWRUbyddO1xuICAgICAgICAgIHRoaXMuYWRkSW5PYmplY3RJZHNJZHMoaWRzLCBxdWVyeSk7XG4gICAgICAgICAgcmV0dXJuIHRoaXMucmVkdWNlUmVsYXRpb25LZXlzKGNsYXNzTmFtZSwgcXVlcnksIHF1ZXJ5T3B0aW9ucyk7XG4gICAgICAgIH0pXG4gICAgICAgIC50aGVuKCgpID0+IHt9KTtcbiAgICB9XG4gIH1cblxuICBhZGRJbk9iamVjdElkc0lkcyhpZHM6ID9BcnJheTxzdHJpbmc+ID0gbnVsbCwgcXVlcnk6IGFueSkge1xuICAgIGNvbnN0IGlkc0Zyb21TdHJpbmc6ID9BcnJheTxzdHJpbmc+ID1cbiAgICAgIHR5cGVvZiBxdWVyeS5vYmplY3RJZCA9PT0gJ3N0cmluZycgPyBbcXVlcnkub2JqZWN0SWRdIDogbnVsbDtcbiAgICBjb25zdCBpZHNGcm9tRXE6ID9BcnJheTxzdHJpbmc+ID1cbiAgICAgIHF1ZXJ5Lm9iamVjdElkICYmIHF1ZXJ5Lm9iamVjdElkWyckZXEnXSA/IFtxdWVyeS5vYmplY3RJZFsnJGVxJ11dIDogbnVsbDtcbiAgICBjb25zdCBpZHNGcm9tSW46ID9BcnJheTxzdHJpbmc+ID1cbiAgICAgIHF1ZXJ5Lm9iamVjdElkICYmIHF1ZXJ5Lm9iamVjdElkWyckaW4nXSA/IHF1ZXJ5Lm9iamVjdElkWyckaW4nXSA6IG51bGw7XG5cbiAgICAvLyBAZmxvdy1kaXNhYmxlLW5leHRcbiAgICBjb25zdCBhbGxJZHM6IEFycmF5PEFycmF5PHN0cmluZz4+ID0gW1xuICAgICAgaWRzRnJvbVN0cmluZyxcbiAgICAgIGlkc0Zyb21FcSxcbiAgICAgIGlkc0Zyb21JbixcbiAgICAgIGlkcyxcbiAgICBdLmZpbHRlcihsaXN0ID0+IGxpc3QgIT09IG51bGwpO1xuICAgIGNvbnN0IHRvdGFsTGVuZ3RoID0gYWxsSWRzLnJlZHVjZSgobWVtbywgbGlzdCkgPT4gbWVtbyArIGxpc3QubGVuZ3RoLCAwKTtcblxuICAgIGxldCBpZHNJbnRlcnNlY3Rpb24gPSBbXTtcbiAgICBpZiAodG90YWxMZW5ndGggPiAxMjUpIHtcbiAgICAgIGlkc0ludGVyc2VjdGlvbiA9IGludGVyc2VjdC5iaWcoYWxsSWRzKTtcbiAgICB9IGVsc2Uge1xuICAgICAgaWRzSW50ZXJzZWN0aW9uID0gaW50ZXJzZWN0KGFsbElkcyk7XG4gICAgfVxuXG4gICAgLy8gTmVlZCB0byBtYWtlIHN1cmUgd2UgZG9uJ3QgY2xvYmJlciBleGlzdGluZyBzaG9ydGhhbmQgJGVxIGNvbnN0cmFpbnRzIG9uIG9iamVjdElkLlxuICAgIGlmICghKCdvYmplY3RJZCcgaW4gcXVlcnkpKSB7XG4gICAgICBxdWVyeS5vYmplY3RJZCA9IHtcbiAgICAgICAgJGluOiB1bmRlZmluZWQsXG4gICAgICB9O1xuICAgIH0gZWxzZSBpZiAodHlwZW9mIHF1ZXJ5Lm9iamVjdElkID09PSAnc3RyaW5nJykge1xuICAgICAgcXVlcnkub2JqZWN0SWQgPSB7XG4gICAgICAgICRpbjogdW5kZWZpbmVkLFxuICAgICAgICAkZXE6IHF1ZXJ5Lm9iamVjdElkLFxuICAgICAgfTtcbiAgICB9XG4gICAgcXVlcnkub2JqZWN0SWRbJyRpbiddID0gaWRzSW50ZXJzZWN0aW9uO1xuXG4gICAgcmV0dXJuIHF1ZXJ5O1xuICB9XG5cbiAgYWRkTm90SW5PYmplY3RJZHNJZHMoaWRzOiBzdHJpbmdbXSA9IFtdLCBxdWVyeTogYW55KSB7XG4gICAgY29uc3QgaWRzRnJvbU5pbiA9XG4gICAgICBxdWVyeS5vYmplY3RJZCAmJiBxdWVyeS5vYmplY3RJZFsnJG5pbiddID8gcXVlcnkub2JqZWN0SWRbJyRuaW4nXSA6IFtdO1xuICAgIGxldCBhbGxJZHMgPSBbLi4uaWRzRnJvbU5pbiwgLi4uaWRzXS5maWx0ZXIobGlzdCA9PiBsaXN0ICE9PSBudWxsKTtcblxuICAgIC8vIG1ha2UgYSBzZXQgYW5kIHNwcmVhZCB0byByZW1vdmUgZHVwbGljYXRlc1xuICAgIGFsbElkcyA9IFsuLi5uZXcgU2V0KGFsbElkcyldO1xuXG4gICAgLy8gTmVlZCB0byBtYWtlIHN1cmUgd2UgZG9uJ3QgY2xvYmJlciBleGlzdGluZyBzaG9ydGhhbmQgJGVxIGNvbnN0cmFpbnRzIG9uIG9iamVjdElkLlxuICAgIGlmICghKCdvYmplY3RJZCcgaW4gcXVlcnkpKSB7XG4gICAgICBxdWVyeS5vYmplY3RJZCA9IHtcbiAgICAgICAgJG5pbjogdW5kZWZpbmVkLFxuICAgICAgfTtcbiAgICB9IGVsc2UgaWYgKHR5cGVvZiBxdWVyeS5vYmplY3RJZCA9PT0gJ3N0cmluZycpIHtcbiAgICAgIHF1ZXJ5Lm9iamVjdElkID0ge1xuICAgICAgICAkbmluOiB1bmRlZmluZWQsXG4gICAgICAgICRlcTogcXVlcnkub2JqZWN0SWQsXG4gICAgICB9O1xuICAgIH1cblxuICAgIHF1ZXJ5Lm9iamVjdElkWyckbmluJ10gPSBhbGxJZHM7XG4gICAgcmV0dXJuIHF1ZXJ5O1xuICB9XG5cbiAgLy8gUnVucyBhIHF1ZXJ5IG9uIHRoZSBkYXRhYmFzZS5cbiAgLy8gUmV0dXJucyBhIHByb21pc2UgdGhhdCByZXNvbHZlcyB0byBhIGxpc3Qgb2YgaXRlbXMuXG4gIC8vIE9wdGlvbnM6XG4gIC8vICAgc2tpcCAgICBudW1iZXIgb2YgcmVzdWx0cyB0byBza2lwLlxuICAvLyAgIGxpbWl0ICAgbGltaXQgdG8gdGhpcyBudW1iZXIgb2YgcmVzdWx0cy5cbiAgLy8gICBzb3J0ICAgIGFuIG9iamVjdCB3aGVyZSBrZXlzIGFyZSB0aGUgZmllbGRzIHRvIHNvcnQgYnkuXG4gIC8vICAgICAgICAgICB0aGUgdmFsdWUgaXMgKzEgZm9yIGFzY2VuZGluZywgLTEgZm9yIGRlc2NlbmRpbmcuXG4gIC8vICAgY291bnQgICBydW4gYSBjb3VudCBpbnN0ZWFkIG9mIHJldHVybmluZyByZXN1bHRzLlxuICAvLyAgIGFjbCAgICAgcmVzdHJpY3QgdGhpcyBvcGVyYXRpb24gd2l0aCBhbiBBQ0wgZm9yIHRoZSBwcm92aWRlZCBhcnJheVxuICAvLyAgICAgICAgICAgb2YgdXNlciBvYmplY3RJZHMgYW5kIHJvbGVzLiBhY2w6IG51bGwgbWVhbnMgbm8gdXNlci5cbiAgLy8gICAgICAgICAgIHdoZW4gdGhpcyBmaWVsZCBpcyBub3QgcHJlc2VudCwgZG9uJ3QgZG8gYW55dGhpbmcgcmVnYXJkaW5nIEFDTHMuXG4gIC8vICBjYXNlSW5zZW5zaXRpdmUgbWFrZSBzdHJpbmcgY29tcGFyaXNvbnMgY2FzZSBpbnNlbnNpdGl2ZVxuICAvLyBUT0RPOiBtYWtlIHVzZXJJZHMgbm90IG5lZWRlZCBoZXJlLiBUaGUgZGIgYWRhcHRlciBzaG91bGRuJ3Qga25vd1xuICAvLyBhbnl0aGluZyBhYm91dCB1c2VycywgaWRlYWxseS4gVGhlbiwgaW1wcm92ZSB0aGUgZm9ybWF0IG9mIHRoZSBBQ0xcbiAgLy8gYXJnIHRvIHdvcmsgbGlrZSB0aGUgb3RoZXJzLlxuICBmaW5kKFxuICAgIGNsYXNzTmFtZTogc3RyaW5nLFxuICAgIHF1ZXJ5OiBhbnksXG4gICAge1xuICAgICAgc2tpcCxcbiAgICAgIGxpbWl0LFxuICAgICAgYWNsLFxuICAgICAgc29ydCA9IHt9LFxuICAgICAgY291bnQsXG4gICAgICBrZXlzLFxuICAgICAgb3AsXG4gICAgICBkaXN0aW5jdCxcbiAgICAgIHBpcGVsaW5lLFxuICAgICAgcmVhZFByZWZlcmVuY2UsXG4gICAgICBoaW50LFxuICAgICAgY2FzZUluc2Vuc2l0aXZlID0gZmFsc2UsXG4gICAgICBleHBsYWluLFxuICAgIH06IGFueSA9IHt9LFxuICAgIGF1dGg6IGFueSA9IHt9LFxuICAgIHZhbGlkU2NoZW1hQ29udHJvbGxlcjogU2NoZW1hQ29udHJvbGxlci5TY2hlbWFDb250cm9sbGVyXG4gICk6IFByb21pc2U8YW55PiB7XG4gICAgY29uc3QgaXNNYXN0ZXIgPSBhY2wgPT09IHVuZGVmaW5lZDtcbiAgICBjb25zdCBhY2xHcm91cCA9IGFjbCB8fCBbXTtcbiAgICBvcCA9XG4gICAgICBvcCB8fFxuICAgICAgKHR5cGVvZiBxdWVyeS5vYmplY3RJZCA9PSAnc3RyaW5nJyAmJiBPYmplY3Qua2V5cyhxdWVyeSkubGVuZ3RoID09PSAxXG4gICAgICAgID8gJ2dldCdcbiAgICAgICAgOiAnZmluZCcpO1xuICAgIC8vIENvdW50IG9wZXJhdGlvbiBpZiBjb3VudGluZ1xuICAgIG9wID0gY291bnQgPT09IHRydWUgPyAnY291bnQnIDogb3A7XG5cbiAgICBsZXQgY2xhc3NFeGlzdHMgPSB0cnVlO1xuICAgIHJldHVybiB0aGlzLmxvYWRTY2hlbWFJZk5lZWRlZCh2YWxpZFNjaGVtYUNvbnRyb2xsZXIpLnRoZW4oXG4gICAgICBzY2hlbWFDb250cm9sbGVyID0+IHtcbiAgICAgICAgLy9BbGxvdyB2b2xhdGlsZSBjbGFzc2VzIGlmIHF1ZXJ5aW5nIHdpdGggTWFzdGVyIChmb3IgX1B1c2hTdGF0dXMpXG4gICAgICAgIC8vVE9ETzogTW92ZSB2b2xhdGlsZSBjbGFzc2VzIGNvbmNlcHQgaW50byBtb25nbyBhZGFwdGVyLCBwb3N0Z3JlcyBhZGFwdGVyIHNob3VsZG4ndCBjYXJlXG4gICAgICAgIC8vdGhhdCBhcGkucGFyc2UuY29tIGJyZWFrcyB3aGVuIF9QdXNoU3RhdHVzIGV4aXN0cyBpbiBtb25nby5cbiAgICAgICAgcmV0dXJuIHNjaGVtYUNvbnRyb2xsZXJcbiAgICAgICAgICAuZ2V0T25lU2NoZW1hKGNsYXNzTmFtZSwgaXNNYXN0ZXIpXG4gICAgICAgICAgLmNhdGNoKGVycm9yID0+IHtcbiAgICAgICAgICAgIC8vIEJlaGF2aW9yIGZvciBub24tZXhpc3RlbnQgY2xhc3NlcyBpcyBraW5kYSB3ZWlyZCBvbiBQYXJzZS5jb20uIFByb2JhYmx5IGRvZXNuJ3QgbWF0dGVyIHRvbyBtdWNoLlxuICAgICAgICAgICAgLy8gRm9yIG5vdywgcHJldGVuZCB0aGUgY2xhc3MgZXhpc3RzIGJ1dCBoYXMgbm8gb2JqZWN0cyxcbiAgICAgICAgICAgIGlmIChlcnJvciA9PT0gdW5kZWZpbmVkKSB7XG4gICAgICAgICAgICAgIGNsYXNzRXhpc3RzID0gZmFsc2U7XG4gICAgICAgICAgICAgIHJldHVybiB7IGZpZWxkczoge30gfTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIHRocm93IGVycm9yO1xuICAgICAgICAgIH0pXG4gICAgICAgICAgLnRoZW4oc2NoZW1hID0+IHtcbiAgICAgICAgICAgIC8vIFBhcnNlLmNvbSB0cmVhdHMgcXVlcmllcyBvbiBfY3JlYXRlZF9hdCBhbmQgX3VwZGF0ZWRfYXQgYXMgaWYgdGhleSB3ZXJlIHF1ZXJpZXMgb24gY3JlYXRlZEF0IGFuZCB1cGRhdGVkQXQsXG4gICAgICAgICAgICAvLyBzbyBkdXBsaWNhdGUgdGhhdCBiZWhhdmlvciBoZXJlLiBJZiBib3RoIGFyZSBzcGVjaWZpZWQsIHRoZSBjb3JyZWN0IGJlaGF2aW9yIHRvIG1hdGNoIFBhcnNlLmNvbSBpcyB0b1xuICAgICAgICAgICAgLy8gdXNlIHRoZSBvbmUgdGhhdCBhcHBlYXJzIGZpcnN0IGluIHRoZSBzb3J0IGxpc3QuXG4gICAgICAgICAgICBpZiAoc29ydC5fY3JlYXRlZF9hdCkge1xuICAgICAgICAgICAgICBzb3J0LmNyZWF0ZWRBdCA9IHNvcnQuX2NyZWF0ZWRfYXQ7XG4gICAgICAgICAgICAgIGRlbGV0ZSBzb3J0Ll9jcmVhdGVkX2F0O1xuICAgICAgICAgICAgfVxuICAgICAgICAgICAgaWYgKHNvcnQuX3VwZGF0ZWRfYXQpIHtcbiAgICAgICAgICAgICAgc29ydC51cGRhdGVkQXQgPSBzb3J0Ll91cGRhdGVkX2F0O1xuICAgICAgICAgICAgICBkZWxldGUgc29ydC5fdXBkYXRlZF9hdDtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIGNvbnN0IHF1ZXJ5T3B0aW9ucyA9IHtcbiAgICAgICAgICAgICAgc2tpcCxcbiAgICAgICAgICAgICAgbGltaXQsXG4gICAgICAgICAgICAgIHNvcnQsXG4gICAgICAgICAgICAgIGtleXMsXG4gICAgICAgICAgICAgIHJlYWRQcmVmZXJlbmNlLFxuICAgICAgICAgICAgICBoaW50LFxuICAgICAgICAgICAgICBjYXNlSW5zZW5zaXRpdmUsXG4gICAgICAgICAgICAgIGV4cGxhaW4sXG4gICAgICAgICAgICB9O1xuICAgICAgICAgICAgT2JqZWN0LmtleXMoc29ydCkuZm9yRWFjaChmaWVsZE5hbWUgPT4ge1xuICAgICAgICAgICAgICBpZiAoZmllbGROYW1lLm1hdGNoKC9eYXV0aERhdGFcXC4oW2EtekEtWjAtOV9dKylcXC5pZCQvKSkge1xuICAgICAgICAgICAgICAgIHRocm93IG5ldyBQYXJzZS5FcnJvcihcbiAgICAgICAgICAgICAgICAgIFBhcnNlLkVycm9yLklOVkFMSURfS0VZX05BTUUsXG4gICAgICAgICAgICAgICAgICBgQ2Fubm90IHNvcnQgYnkgJHtmaWVsZE5hbWV9YFxuICAgICAgICAgICAgICAgICk7XG4gICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgY29uc3Qgcm9vdEZpZWxkTmFtZSA9IGdldFJvb3RGaWVsZE5hbWUoZmllbGROYW1lKTtcbiAgICAgICAgICAgICAgaWYgKCFTY2hlbWFDb250cm9sbGVyLmZpZWxkTmFtZUlzVmFsaWQocm9vdEZpZWxkTmFtZSkpIHtcbiAgICAgICAgICAgICAgICB0aHJvdyBuZXcgUGFyc2UuRXJyb3IoXG4gICAgICAgICAgICAgICAgICBQYXJzZS5FcnJvci5JTlZBTElEX0tFWV9OQU1FLFxuICAgICAgICAgICAgICAgICAgYEludmFsaWQgZmllbGQgbmFtZTogJHtmaWVsZE5hbWV9LmBcbiAgICAgICAgICAgICAgICApO1xuICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9KTtcbiAgICAgICAgICAgIHJldHVybiAoaXNNYXN0ZXJcbiAgICAgICAgICAgICAgPyBQcm9taXNlLnJlc29sdmUoKVxuICAgICAgICAgICAgICA6IHNjaGVtYUNvbnRyb2xsZXIudmFsaWRhdGVQZXJtaXNzaW9uKGNsYXNzTmFtZSwgYWNsR3JvdXAsIG9wKVxuICAgICAgICAgICAgKVxuICAgICAgICAgICAgICAudGhlbigoKSA9PlxuICAgICAgICAgICAgICAgIHRoaXMucmVkdWNlUmVsYXRpb25LZXlzKGNsYXNzTmFtZSwgcXVlcnksIHF1ZXJ5T3B0aW9ucylcbiAgICAgICAgICAgICAgKVxuICAgICAgICAgICAgICAudGhlbigoKSA9PlxuICAgICAgICAgICAgICAgIHRoaXMucmVkdWNlSW5SZWxhdGlvbihjbGFzc05hbWUsIHF1ZXJ5LCBzY2hlbWFDb250cm9sbGVyKVxuICAgICAgICAgICAgICApXG4gICAgICAgICAgICAgIC50aGVuKCgpID0+IHtcbiAgICAgICAgICAgICAgICBsZXQgcHJvdGVjdGVkRmllbGRzO1xuICAgICAgICAgICAgICAgIGlmICghaXNNYXN0ZXIpIHtcbiAgICAgICAgICAgICAgICAgIHF1ZXJ5ID0gdGhpcy5hZGRQb2ludGVyUGVybWlzc2lvbnMoXG4gICAgICAgICAgICAgICAgICAgIHNjaGVtYUNvbnRyb2xsZXIsXG4gICAgICAgICAgICAgICAgICAgIGNsYXNzTmFtZSxcbiAgICAgICAgICAgICAgICAgICAgb3AsXG4gICAgICAgICAgICAgICAgICAgIHF1ZXJ5LFxuICAgICAgICAgICAgICAgICAgICBhY2xHcm91cFxuICAgICAgICAgICAgICAgICAgKTtcbiAgICAgICAgICAgICAgICAgIC8qIERvbid0IHVzZSBwcm9qZWN0aW9ucyB0byBvcHRpbWl6ZSB0aGUgcHJvdGVjdGVkRmllbGRzIHNpbmNlIHRoZSBwcm90ZWN0ZWRGaWVsZHNcbiAgICAgICAgICAgICAgICAgIGJhc2VkIG9uIHBvaW50ZXItcGVybWlzc2lvbnMgYXJlIGRldGVybWluZWQgYWZ0ZXIgcXVlcnlpbmcuIFRoZSBmaWx0ZXJpbmcgY2FuXG4gICAgICAgICAgICAgICAgICBvdmVyd3JpdGUgdGhlIHByb3RlY3RlZCBmaWVsZHMuICovXG4gICAgICAgICAgICAgICAgICBwcm90ZWN0ZWRGaWVsZHMgPSB0aGlzLmFkZFByb3RlY3RlZEZpZWxkcyhcbiAgICAgICAgICAgICAgICAgICAgc2NoZW1hQ29udHJvbGxlcixcbiAgICAgICAgICAgICAgICAgICAgY2xhc3NOYW1lLFxuICAgICAgICAgICAgICAgICAgICBxdWVyeSxcbiAgICAgICAgICAgICAgICAgICAgYWNsR3JvdXAsXG4gICAgICAgICAgICAgICAgICAgIGF1dGhcbiAgICAgICAgICAgICAgICAgICk7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGlmICghcXVlcnkpIHtcbiAgICAgICAgICAgICAgICAgIGlmIChvcCA9PT0gJ2dldCcpIHtcbiAgICAgICAgICAgICAgICAgICAgdGhyb3cgbmV3IFBhcnNlLkVycm9yKFxuICAgICAgICAgICAgICAgICAgICAgIFBhcnNlLkVycm9yLk9CSkVDVF9OT1RfRk9VTkQsXG4gICAgICAgICAgICAgICAgICAgICAgJ09iamVjdCBub3QgZm91bmQuJ1xuICAgICAgICAgICAgICAgICAgICApO1xuICAgICAgICAgICAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIFtdO1xuICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBpZiAoIWlzTWFzdGVyKSB7XG4gICAgICAgICAgICAgICAgICBpZiAob3AgPT09ICd1cGRhdGUnIHx8IG9wID09PSAnZGVsZXRlJykge1xuICAgICAgICAgICAgICAgICAgICBxdWVyeSA9IGFkZFdyaXRlQUNMKHF1ZXJ5LCBhY2xHcm91cCk7XG4gICAgICAgICAgICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgICAgICAgICAgICBxdWVyeSA9IGFkZFJlYWRBQ0wocXVlcnksIGFjbEdyb3VwKTtcbiAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgdmFsaWRhdGVRdWVyeShxdWVyeSwgdGhpcy5za2lwTW9uZ29EQlNlcnZlcjEzNzMyV29ya2Fyb3VuZCk7XG4gICAgICAgICAgICAgICAgaWYgKGNvdW50KSB7XG4gICAgICAgICAgICAgICAgICBpZiAoIWNsYXNzRXhpc3RzKSB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiAwO1xuICAgICAgICAgICAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIHRoaXMuYWRhcHRlci5jb3VudChcbiAgICAgICAgICAgICAgICAgICAgICBjbGFzc05hbWUsXG4gICAgICAgICAgICAgICAgICAgICAgc2NoZW1hLFxuICAgICAgICAgICAgICAgICAgICAgIHF1ZXJ5LFxuICAgICAgICAgICAgICAgICAgICAgIHJlYWRQcmVmZXJlbmNlLFxuICAgICAgICAgICAgICAgICAgICAgIHVuZGVmaW5lZCxcbiAgICAgICAgICAgICAgICAgICAgICBoaW50XG4gICAgICAgICAgICAgICAgICAgICk7XG4gICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgfSBlbHNlIGlmIChkaXN0aW5jdCkge1xuICAgICAgICAgICAgICAgICAgaWYgKCFjbGFzc0V4aXN0cykge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gW107XG4gICAgICAgICAgICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gdGhpcy5hZGFwdGVyLmRpc3RpbmN0KFxuICAgICAgICAgICAgICAgICAgICAgIGNsYXNzTmFtZSxcbiAgICAgICAgICAgICAgICAgICAgICBzY2hlbWEsXG4gICAgICAgICAgICAgICAgICAgICAgcXVlcnksXG4gICAgICAgICAgICAgICAgICAgICAgZGlzdGluY3RcbiAgICAgICAgICAgICAgICAgICAgKTtcbiAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICB9IGVsc2UgaWYgKHBpcGVsaW5lKSB7XG4gICAgICAgICAgICAgICAgICBpZiAoIWNsYXNzRXhpc3RzKSB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBbXTtcbiAgICAgICAgICAgICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiB0aGlzLmFkYXB0ZXIuYWdncmVnYXRlKFxuICAgICAgICAgICAgICAgICAgICAgIGNsYXNzTmFtZSxcbiAgICAgICAgICAgICAgICAgICAgICBzY2hlbWEsXG4gICAgICAgICAgICAgICAgICAgICAgcGlwZWxpbmUsXG4gICAgICAgICAgICAgICAgICAgICAgcmVhZFByZWZlcmVuY2UsXG4gICAgICAgICAgICAgICAgICAgICAgaGludCxcbiAgICAgICAgICAgICAgICAgICAgICBleHBsYWluXG4gICAgICAgICAgICAgICAgICAgICk7XG4gICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgfSBlbHNlIGlmIChleHBsYWluKSB7XG4gICAgICAgICAgICAgICAgICByZXR1cm4gdGhpcy5hZGFwdGVyLmZpbmQoXG4gICAgICAgICAgICAgICAgICAgIGNsYXNzTmFtZSxcbiAgICAgICAgICAgICAgICAgICAgc2NoZW1hLFxuICAgICAgICAgICAgICAgICAgICBxdWVyeSxcbiAgICAgICAgICAgICAgICAgICAgcXVlcnlPcHRpb25zXG4gICAgICAgICAgICAgICAgICApO1xuICAgICAgICAgICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgICAgICAgICByZXR1cm4gdGhpcy5hZGFwdGVyXG4gICAgICAgICAgICAgICAgICAgIC5maW5kKGNsYXNzTmFtZSwgc2NoZW1hLCBxdWVyeSwgcXVlcnlPcHRpb25zKVxuICAgICAgICAgICAgICAgICAgICAudGhlbihvYmplY3RzID0+XG4gICAgICAgICAgICAgICAgICAgICAgb2JqZWN0cy5tYXAob2JqZWN0ID0+IHtcbiAgICAgICAgICAgICAgICAgICAgICAgIG9iamVjdCA9IHVudHJhbnNmb3JtT2JqZWN0QUNMKG9iamVjdCk7XG4gICAgICAgICAgICAgICAgICAgICAgICByZXR1cm4gZmlsdGVyU2Vuc2l0aXZlRGF0YShcbiAgICAgICAgICAgICAgICAgICAgICAgICAgaXNNYXN0ZXIsXG4gICAgICAgICAgICAgICAgICAgICAgICAgIGFjbEdyb3VwLFxuICAgICAgICAgICAgICAgICAgICAgICAgICBhdXRoLFxuICAgICAgICAgICAgICAgICAgICAgICAgICBvcCxcbiAgICAgICAgICAgICAgICAgICAgICAgICAgc2NoZW1hQ29udHJvbGxlcixcbiAgICAgICAgICAgICAgICAgICAgICAgICAgY2xhc3NOYW1lLFxuICAgICAgICAgICAgICAgICAgICAgICAgICBwcm90ZWN0ZWRGaWVsZHMsXG4gICAgICAgICAgICAgICAgICAgICAgICAgIG9iamVjdFxuICAgICAgICAgICAgICAgICAgICAgICAgKTtcbiAgICAgICAgICAgICAgICAgICAgICB9KVxuICAgICAgICAgICAgICAgICAgICApXG4gICAgICAgICAgICAgICAgICAgIC5jYXRjaChlcnJvciA9PiB7XG4gICAgICAgICAgICAgICAgICAgICAgdGhyb3cgbmV3IFBhcnNlLkVycm9yKFxuICAgICAgICAgICAgICAgICAgICAgICAgUGFyc2UuRXJyb3IuSU5URVJOQUxfU0VSVkVSX0VSUk9SLFxuICAgICAgICAgICAgICAgICAgICAgICAgZXJyb3JcbiAgICAgICAgICAgICAgICAgICAgICApO1xuICAgICAgICAgICAgICAgICAgICB9KTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgIH0pO1xuICAgICAgICAgIH0pO1xuICAgICAgfVxuICAgICk7XG4gIH1cblxuICBkZWxldGVTY2hlbWEoY2xhc3NOYW1lOiBzdHJpbmcpOiBQcm9taXNlPHZvaWQ+IHtcbiAgICByZXR1cm4gdGhpcy5sb2FkU2NoZW1hKHsgY2xlYXJDYWNoZTogdHJ1ZSB9KVxuICAgICAgLnRoZW4oc2NoZW1hQ29udHJvbGxlciA9PiBzY2hlbWFDb250cm9sbGVyLmdldE9uZVNjaGVtYShjbGFzc05hbWUsIHRydWUpKVxuICAgICAgLmNhdGNoKGVycm9yID0+IHtcbiAgICAgICAgaWYgKGVycm9yID09PSB1bmRlZmluZWQpIHtcbiAgICAgICAgICByZXR1cm4geyBmaWVsZHM6IHt9IH07XG4gICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgdGhyb3cgZXJyb3I7XG4gICAgICAgIH1cbiAgICAgIH0pXG4gICAgICAudGhlbigoc2NoZW1hOiBhbnkpID0+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY29sbGVjdGlvbkV4aXN0cyhjbGFzc05hbWUpXG4gICAgICAgICAgLnRoZW4oKCkgPT5cbiAgICAgICAgICAgIHRoaXMuYWRhcHRlci5jb3VudChjbGFzc05hbWUsIHsgZmllbGRzOiB7fSB9LCBudWxsLCAnJywgZmFsc2UpXG4gICAgICAgICAgKVxuICAgICAgICAgIC50aGVuKGNvdW50ID0+IHtcbiAgICAgICAgICAgIGlmIChjb3VudCA+IDApIHtcbiAgICAgICAgICAgICAgdGhyb3cgbmV3IFBhcnNlLkVycm9yKFxuICAgICAgICAgICAgICAgIDI1NSxcbiAgICAgICAgICAgICAgICBgQ2xhc3MgJHtjbGFzc05hbWV9IGlzIG5vdCBlbXB0eSwgY29udGFpbnMgJHtjb3VudH0gb2JqZWN0cywgY2Fubm90IGRyb3Agc2NoZW1hLmBcbiAgICAgICAgICAgICAgKTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIHJldHVybiB0aGlzLmFkYXB0ZXIuZGVsZXRlQ2xhc3MoY2xhc3NOYW1lKTtcbiAgICAgICAgICB9KVxuICAgICAgICAgIC50aGVuKHdhc1BhcnNlQ29sbGVjdGlvbiA9PiB7XG4gICAgICAgICAgICBpZiAod2FzUGFyc2VDb2xsZWN0aW9uKSB7XG4gICAgICAgICAgICAgIGNvbnN0IHJlbGF0aW9uRmllbGROYW1lcyA9IE9iamVjdC5rZXlzKHNjaGVtYS5maWVsZHMpLmZpbHRlcihcbiAgICAgICAgICAgICAgICBmaWVsZE5hbWUgPT4gc2NoZW1hLmZpZWxkc1tmaWVsZE5hbWVdLnR5cGUgPT09ICdSZWxhdGlvbidcbiAgICAgICAgICAgICAgKTtcbiAgICAgICAgICAgICAgcmV0dXJuIFByb21pc2UuYWxsKFxuICAgICAgICAgICAgICAgIHJlbGF0aW9uRmllbGROYW1lcy5tYXAobmFtZSA9PlxuICAgICAgICAgICAgICAgICAgdGhpcy5hZGFwdGVyLmRlbGV0ZUNsYXNzKGpvaW5UYWJsZU5hbWUoY2xhc3NOYW1lLCBuYW1lKSlcbiAgICAgICAgICAgICAgICApXG4gICAgICAgICAgICAgICkudGhlbigoKSA9PiB7XG4gICAgICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgICAgICB9KTtcbiAgICAgICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgICAgIHJldHVybiBQcm9taXNlLnJlc29sdmUoKTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICB9KTtcbiAgICAgIH0pO1xuICB9XG5cbiAgLy8gQ29uc3RyYWludHMgcXVlcnkgdXNpbmcgQ0xQJ3MgcG9pbnRlciBwZXJtaXNzaW9ucyAoUFApIGlmIGFueS5cbiAgLy8gMS4gRXRyYWN0IHRoZSB1c2VyIGlkIGZyb20gY2FsbGVyJ3MgQUNMZ3JvdXA7XG4gIC8vIDIuIEV4Y3RyYWN0IGEgbGlzdCBvZiBmaWVsZCBuYW1lcyB0aGF0IGFyZSBQUCBmb3IgdGFyZ2V0IGNvbGxlY3Rpb24gYW5kIG9wZXJhdGlvbjtcbiAgLy8gMy4gQ29uc3RyYWludCB0aGUgb3JpZ2luYWwgcXVlcnkgc28gdGhhdCBlYWNoIFBQIGZpZWxkIG11c3RcbiAgLy8gcG9pbnQgdG8gY2FsbGVyJ3MgaWQgKG9yIGNvbnRhaW4gaXQgaW4gY2FzZSBvZiBQUCBmaWVsZCBiZWluZyBhbiBhcnJheSlcbiAgYWRkUG9pbnRlclBlcm1pc3Npb25zKFxuICAgIHNjaGVtYTogU2NoZW1hQ29udHJvbGxlci5TY2hlbWFDb250cm9sbGVyLFxuICAgIGNsYXNzTmFtZTogc3RyaW5nLFxuICAgIG9wZXJhdGlvbjogc3RyaW5nLFxuICAgIHF1ZXJ5OiBhbnksXG4gICAgYWNsR3JvdXA6IGFueVtdID0gW11cbiAgKTogYW55IHtcbiAgICAvLyBDaGVjayBpZiBjbGFzcyBoYXMgcHVibGljIHBlcm1pc3Npb24gZm9yIG9wZXJhdGlvblxuICAgIC8vIElmIHRoZSBCYXNlQ0xQIHBhc3MsIGxldCBnbyB0aHJvdWdoXG4gICAgaWYgKHNjaGVtYS50ZXN0UGVybWlzc2lvbnNGb3JDbGFzc05hbWUoY2xhc3NOYW1lLCBhY2xHcm91cCwgb3BlcmF0aW9uKSkge1xuICAgICAgcmV0dXJuIHF1ZXJ5O1xuICAgIH1cbiAgICBjb25zdCBwZXJtcyA9IHNjaGVtYS5nZXRDbGFzc0xldmVsUGVybWlzc2lvbnMoY2xhc3NOYW1lKTtcblxuICAgIGNvbnN0IHVzZXJBQ0wgPSBhY2xHcm91cC5maWx0ZXIoYWNsID0+IHtcbiAgICAgIHJldHVybiBhY2wuaW5kZXhPZigncm9sZTonKSAhPSAwICYmIGFjbCAhPSAnKic7XG4gICAgfSk7XG5cbiAgICBjb25zdCBncm91cEtleSA9XG4gICAgICBbJ2dldCcsICdmaW5kJywgJ2NvdW50J10uaW5kZXhPZihvcGVyYXRpb24pID4gLTFcbiAgICAgICAgPyAncmVhZFVzZXJGaWVsZHMnXG4gICAgICAgIDogJ3dyaXRlVXNlckZpZWxkcyc7XG5cbiAgICBjb25zdCBwZXJtRmllbGRzID0gW107XG5cbiAgICBpZiAocGVybXNbb3BlcmF0aW9uXSAmJiBwZXJtc1tvcGVyYXRpb25dLnBvaW50ZXJGaWVsZHMpIHtcbiAgICAgIHBlcm1GaWVsZHMucHVzaCguLi5wZXJtc1tvcGVyYXRpb25dLnBvaW50ZXJGaWVsZHMpO1xuICAgIH1cblxuICAgIGlmIChwZXJtc1tncm91cEtleV0pIHtcbiAgICAgIGZvciAoY29uc3QgZmllbGQgb2YgcGVybXNbZ3JvdXBLZXldKSB7XG4gICAgICAgIGlmICghcGVybUZpZWxkcy5pbmNsdWRlcyhmaWVsZCkpIHtcbiAgICAgICAgICBwZXJtRmllbGRzLnB1c2goZmllbGQpO1xuICAgICAgICB9XG4gICAgICB9XG4gICAgfVxuICAgIC8vIHRoZSBBQ0wgc2hvdWxkIGhhdmUgZXhhY3RseSAxIHVzZXJcbiAgICBpZiAocGVybUZpZWxkcy5sZW5ndGggPiAwKSB7XG4gICAgICAvLyB0aGUgQUNMIHNob3VsZCBoYXZlIGV4YWN0bHkgMSB1c2VyXG4gICAgICAvLyBObyB1c2VyIHNldCByZXR1cm4gdW5kZWZpbmVkXG4gICAgICAvLyBJZiB0aGUgbGVuZ3RoIGlzID4gMSwgdGhhdCBtZWFucyB3ZSBkaWRuJ3QgZGUtZHVwZSB1c2VycyBjb3JyZWN0bHlcbiAgICAgIGlmICh1c2VyQUNMLmxlbmd0aCAhPSAxKSB7XG4gICAgICAgIHJldHVybjtcbiAgICAgIH1cbiAgICAgIGNvbnN0IHVzZXJJZCA9IHVzZXJBQ0xbMF07XG4gICAgICBjb25zdCB1c2VyUG9pbnRlciA9IHtcbiAgICAgICAgX190eXBlOiAnUG9pbnRlcicsXG4gICAgICAgIGNsYXNzTmFtZTogJ19Vc2VyJyxcbiAgICAgICAgb2JqZWN0SWQ6IHVzZXJJZCxcbiAgICAgIH07XG5cbiAgICAgIGNvbnN0IG9ycyA9IHBlcm1GaWVsZHMuZmxhdE1hcChrZXkgPT4ge1xuICAgICAgICAvLyBjb25zdHJhaW50IGZvciBzaW5nbGUgcG9pbnRlciBzZXR1cFxuICAgICAgICBjb25zdCBxID0ge1xuICAgICAgICAgIFtrZXldOiB1c2VyUG9pbnRlcixcbiAgICAgICAgfTtcbiAgICAgICAgLy8gY29uc3RyYWludCBmb3IgdXNlcnMtYXJyYXkgc2V0dXBcbiAgICAgICAgY29uc3QgcWEgPSB7XG4gICAgICAgICAgW2tleV06IHsgJGFsbDogW3VzZXJQb2ludGVyXSB9LFxuICAgICAgICB9O1xuICAgICAgICAvLyBpZiB3ZSBhbHJlYWR5IGhhdmUgYSBjb25zdHJhaW50IG9uIHRoZSBrZXksIHVzZSB0aGUgJGFuZFxuICAgICAgICBpZiAoT2JqZWN0LnByb3RvdHlwZS5oYXNPd25Qcm9wZXJ0eS5jYWxsKHF1ZXJ5LCBrZXkpKSB7XG4gICAgICAgICAgcmV0dXJuIFt7ICRhbmQ6IFtxLCBxdWVyeV0gfSwgeyAkYW5kOiBbcWEsIHF1ZXJ5XSB9XTtcbiAgICAgICAgfVxuICAgICAgICAvLyBvdGhlcndpc2UganVzdCBhZGQgdGhlIGNvbnN0YWludFxuICAgICAgICByZXR1cm4gW09iamVjdC5hc3NpZ24oe30sIHF1ZXJ5LCBxKSwgT2JqZWN0LmFzc2lnbih7fSwgcXVlcnksIHFhKV07XG4gICAgICB9KTtcbiAgICAgIHJldHVybiB7ICRvcjogb3JzIH07XG4gICAgfSBlbHNlIHtcbiAgICAgIHJldHVybiBxdWVyeTtcbiAgICB9XG4gIH1cblxuICBhZGRQcm90ZWN0ZWRGaWVsZHMoXG4gICAgc2NoZW1hOiBTY2hlbWFDb250cm9sbGVyLlNjaGVtYUNvbnRyb2xsZXIsXG4gICAgY2xhc3NOYW1lOiBzdHJpbmcsXG4gICAgcXVlcnk6IGFueSA9IHt9LFxuICAgIGFjbEdyb3VwOiBhbnlbXSA9IFtdLFxuICAgIGF1dGg6IGFueSA9IHt9XG4gICk6IG51bGwgfCBzdHJpbmdbXSB7XG4gICAgY29uc3QgcGVybXMgPSBzY2hlbWEuZ2V0Q2xhc3NMZXZlbFBlcm1pc3Npb25zKGNsYXNzTmFtZSk7XG4gICAgaWYgKCFwZXJtcykgcmV0dXJuIG51bGw7XG5cbiAgICBjb25zdCBwcm90ZWN0ZWRGaWVsZHMgPSBwZXJtcy5wcm90ZWN0ZWRGaWVsZHM7XG4gICAgaWYgKCFwcm90ZWN0ZWRGaWVsZHMpIHJldHVybiBudWxsO1xuXG4gICAgaWYgKGFjbEdyb3VwLmluZGV4T2YocXVlcnkub2JqZWN0SWQpID4gLTEpIHJldHVybiBudWxsO1xuXG4gICAgLy8gcmVtb3ZlIHVzZXJGaWVsZCBrZXlzIHNpbmNlIHRoZXkgYXJlIGZpbHRlcmVkIGFmdGVyIHF1ZXJ5aW5nXG4gICAgbGV0IHByb3RlY3RlZEtleXMgPSBPYmplY3Qua2V5cyhwcm90ZWN0ZWRGaWVsZHMpLnJlZHVjZSgoYWNjLCB2YWwpID0+IHtcbiAgICAgIGlmICh2YWwuc3RhcnRzV2l0aCgndXNlckZpZWxkOicpKSByZXR1cm4gYWNjO1xuICAgICAgcmV0dXJuIGFjYy5jb25jYXQocHJvdGVjdGVkRmllbGRzW3ZhbF0pO1xuICAgIH0sIFtdKTtcblxuICAgIFsuLi4oYXV0aC51c2VyUm9sZXMgfHwgW10pXS5mb3JFYWNoKHJvbGUgPT4ge1xuICAgICAgY29uc3QgZmllbGRzID0gcHJvdGVjdGVkRmllbGRzW3JvbGVdO1xuICAgICAgaWYgKGZpZWxkcykge1xuICAgICAgICBwcm90ZWN0ZWRLZXlzID0gcHJvdGVjdGVkS2V5cy5maWx0ZXIodiA9PiBmaWVsZHMuaW5jbHVkZXModikpO1xuICAgICAgfVxuICAgIH0pO1xuXG4gICAgcmV0dXJuIHByb3RlY3RlZEtleXM7XG4gIH1cblxuICBjcmVhdGVUcmFuc2FjdGlvbmFsU2Vzc2lvbigpIHtcbiAgICByZXR1cm4gdGhpcy5hZGFwdGVyXG4gICAgICAuY3JlYXRlVHJhbnNhY3Rpb25hbFNlc3Npb24oKVxuICAgICAgLnRoZW4odHJhbnNhY3Rpb25hbFNlc3Npb24gPT4ge1xuICAgICAgICB0aGlzLl90cmFuc2FjdGlvbmFsU2Vzc2lvbiA9IHRyYW5zYWN0aW9uYWxTZXNzaW9uO1xuICAgICAgfSk7XG4gIH1cblxuICBjb21taXRUcmFuc2FjdGlvbmFsU2Vzc2lvbigpIHtcbiAgICBpZiAoIXRoaXMuX3RyYW5zYWN0aW9uYWxTZXNzaW9uKSB7XG4gICAgICB0aHJvdyBuZXcgRXJyb3IoJ1RoZXJlIGlzIG5vIHRyYW5zYWN0aW9uYWwgc2Vzc2lvbiB0byBjb21taXQnKTtcbiAgICB9XG4gICAgcmV0dXJuIHRoaXMuYWRhcHRlclxuICAgICAgLmNvbW1pdFRyYW5zYWN0aW9uYWxTZXNzaW9uKHRoaXMuX3RyYW5zYWN0aW9uYWxTZXNzaW9uKVxuICAgICAgLnRoZW4oKCkgPT4ge1xuICAgICAgICB0aGlzLl90cmFuc2FjdGlvbmFsU2Vzc2lvbiA9IG51bGw7XG4gICAgICB9KTtcbiAgfVxuXG4gIGFib3J0VHJhbnNhY3Rpb25hbFNlc3Npb24oKSB7XG4gICAgaWYgKCF0aGlzLl90cmFuc2FjdGlvbmFsU2Vzc2lvbikge1xuICAgICAgdGhyb3cgbmV3IEVycm9yKCdUaGVyZSBpcyBubyB0cmFuc2FjdGlvbmFsIHNlc3Npb24gdG8gYWJvcnQnKTtcbiAgICB9XG4gICAgcmV0dXJuIHRoaXMuYWRhcHRlclxuICAgICAgLmFib3J0VHJhbnNhY3Rpb25hbFNlc3Npb24odGhpcy5fdHJhbnNhY3Rpb25hbFNlc3Npb24pXG4gICAgICAudGhlbigoKSA9PiB7XG4gICAgICAgIHRoaXMuX3RyYW5zYWN0aW9uYWxTZXNzaW9uID0gbnVsbDtcbiAgICAgIH0pO1xuICB9XG5cbiAgLy8gVE9ETzogY3JlYXRlIGluZGV4ZXMgb24gZmlyc3QgY3JlYXRpb24gb2YgYSBfVXNlciBvYmplY3QuIE90aGVyd2lzZSBpdCdzIGltcG9zc2libGUgdG9cbiAgLy8gaGF2ZSBhIFBhcnNlIGFwcCB3aXRob3V0IGl0IGhhdmluZyBhIF9Vc2VyIGNvbGxlY3Rpb24uXG4gIHBlcmZvcm1Jbml0aWFsaXphdGlvbigpIHtcbiAgICBjb25zdCByZXF1aXJlZFVzZXJGaWVsZHMgPSB7XG4gICAgICBmaWVsZHM6IHtcbiAgICAgICAgLi4uU2NoZW1hQ29udHJvbGxlci5kZWZhdWx0Q29sdW1ucy5fRGVmYXVsdCxcbiAgICAgICAgLi4uU2NoZW1hQ29udHJvbGxlci5kZWZhdWx0Q29sdW1ucy5fVXNlcixcbiAgICAgIH0sXG4gICAgfTtcbiAgICBjb25zdCByZXF1aXJlZFJvbGVGaWVsZHMgPSB7XG4gICAgICBmaWVsZHM6IHtcbiAgICAgICAgLi4uU2NoZW1hQ29udHJvbGxlci5kZWZhdWx0Q29sdW1ucy5fRGVmYXVsdCxcbiAgICAgICAgLi4uU2NoZW1hQ29udHJvbGxlci5kZWZhdWx0Q29sdW1ucy5fUm9sZSxcbiAgICAgIH0sXG4gICAgfTtcblxuICAgIGNvbnN0IHVzZXJDbGFzc1Byb21pc2UgPSB0aGlzLmxvYWRTY2hlbWEoKS50aGVuKHNjaGVtYSA9PlxuICAgICAgc2NoZW1hLmVuZm9yY2VDbGFzc0V4aXN0cygnX1VzZXInKVxuICAgICk7XG4gICAgY29uc3Qgcm9sZUNsYXNzUHJvbWlzZSA9IHRoaXMubG9hZFNjaGVtYSgpLnRoZW4oc2NoZW1hID0+XG4gICAgICBzY2hlbWEuZW5mb3JjZUNsYXNzRXhpc3RzKCdfUm9sZScpXG4gICAgKTtcblxuICAgIGNvbnN0IHVzZXJuYW1lVW5pcXVlbmVzcyA9IHVzZXJDbGFzc1Byb21pc2VcbiAgICAgIC50aGVuKCgpID0+XG4gICAgICAgIHRoaXMuYWRhcHRlci5lbnN1cmVVbmlxdWVuZXNzKCdfVXNlcicsIHJlcXVpcmVkVXNlckZpZWxkcywgWyd1c2VybmFtZSddKVxuICAgICAgKVxuICAgICAgLmNhdGNoKGVycm9yID0+IHtcbiAgICAgICAgbG9nZ2VyLndhcm4oJ1VuYWJsZSB0byBlbnN1cmUgdW5pcXVlbmVzcyBmb3IgdXNlcm5hbWVzOiAnLCBlcnJvcik7XG4gICAgICAgIHRocm93IGVycm9yO1xuICAgICAgfSk7XG5cbiAgICBjb25zdCB1c2VybmFtZUNhc2VJbnNlbnNpdGl2ZUluZGV4ID0gdXNlckNsYXNzUHJvbWlzZVxuICAgICAgLnRoZW4oKCkgPT5cbiAgICAgICAgdGhpcy5hZGFwdGVyLmVuc3VyZUluZGV4KFxuICAgICAgICAgICdfVXNlcicsXG4gICAgICAgICAgcmVxdWlyZWRVc2VyRmllbGRzLFxuICAgICAgICAgIFsndXNlcm5hbWUnXSxcbiAgICAgICAgICAnY2FzZV9pbnNlbnNpdGl2ZV91c2VybmFtZScsXG4gICAgICAgICAgdHJ1ZVxuICAgICAgICApXG4gICAgICApXG4gICAgICAuY2F0Y2goZXJyb3IgPT4ge1xuICAgICAgICBsb2dnZXIud2FybihcbiAgICAgICAgICAnVW5hYmxlIHRvIGNyZWF0ZSBjYXNlIGluc2Vuc2l0aXZlIHVzZXJuYW1lIGluZGV4OiAnLFxuICAgICAgICAgIGVycm9yXG4gICAgICAgICk7XG4gICAgICAgIHRocm93IGVycm9yO1xuICAgICAgfSk7XG5cbiAgICBjb25zdCBlbWFpbFVuaXF1ZW5lc3MgPSB1c2VyQ2xhc3NQcm9taXNlXG4gICAgICAudGhlbigoKSA9PlxuICAgICAgICB0aGlzLmFkYXB0ZXIuZW5zdXJlVW5pcXVlbmVzcygnX1VzZXInLCByZXF1aXJlZFVzZXJGaWVsZHMsIFsnZW1haWwnXSlcbiAgICAgIClcbiAgICAgIC5jYXRjaChlcnJvciA9PiB7XG4gICAgICAgIGxvZ2dlci53YXJuKFxuICAgICAgICAgICdVbmFibGUgdG8gZW5zdXJlIHVuaXF1ZW5lc3MgZm9yIHVzZXIgZW1haWwgYWRkcmVzc2VzOiAnLFxuICAgICAgICAgIGVycm9yXG4gICAgICAgICk7XG4gICAgICAgIHRocm93IGVycm9yO1xuICAgICAgfSk7XG5cbiAgICBjb25zdCBlbWFpbENhc2VJbnNlbnNpdGl2ZUluZGV4ID0gdXNlckNsYXNzUHJvbWlzZVxuICAgICAgLnRoZW4oKCkgPT5cbiAgICAgICAgdGhpcy5hZGFwdGVyLmVuc3VyZUluZGV4KFxuICAgICAgICAgICdfVXNlcicsXG4gICAgICAgICAgcmVxdWlyZWRVc2VyRmllbGRzLFxuICAgICAgICAgIFsnZW1haWwnXSxcbiAgICAgICAgICAnY2FzZV9pbnNlbnNpdGl2ZV9lbWFpbCcsXG4gICAgICAgICAgdHJ1ZVxuICAgICAgICApXG4gICAgICApXG4gICAgICAuY2F0Y2goZXJyb3IgPT4ge1xuICAgICAgICBsb2dnZXIud2FybignVW5hYmxlIHRvIGNyZWF0ZSBjYXNlIGluc2Vuc2l0aXZlIGVtYWlsIGluZGV4OiAnLCBlcnJvcik7XG4gICAgICAgIHRocm93IGVycm9yO1xuICAgICAgfSk7XG5cbiAgICBjb25zdCByb2xlVW5pcXVlbmVzcyA9IHJvbGVDbGFzc1Byb21pc2VcbiAgICAgIC50aGVuKCgpID0+XG4gICAgICAgIHRoaXMuYWRhcHRlci5lbnN1cmVVbmlxdWVuZXNzKCdfUm9sZScsIHJlcXVpcmVkUm9sZUZpZWxkcywgWyduYW1lJ10pXG4gICAgICApXG4gICAgICAuY2F0Y2goZXJyb3IgPT4ge1xuICAgICAgICBsb2dnZXIud2FybignVW5hYmxlIHRvIGVuc3VyZSB1bmlxdWVuZXNzIGZvciByb2xlIG5hbWU6ICcsIGVycm9yKTtcbiAgICAgICAgdGhyb3cgZXJyb3I7XG4gICAgICB9KTtcblxuICAgIGNvbnN0IGluZGV4UHJvbWlzZSA9IHRoaXMuYWRhcHRlci51cGRhdGVTY2hlbWFXaXRoSW5kZXhlcygpO1xuXG4gICAgLy8gQ3JlYXRlIHRhYmxlcyBmb3Igdm9sYXRpbGUgY2xhc3Nlc1xuICAgIGNvbnN0IGFkYXB0ZXJJbml0ID0gdGhpcy5hZGFwdGVyLnBlcmZvcm1Jbml0aWFsaXphdGlvbih7XG4gICAgICBWb2xhdGlsZUNsYXNzZXNTY2hlbWFzOiBTY2hlbWFDb250cm9sbGVyLlZvbGF0aWxlQ2xhc3Nlc1NjaGVtYXMsXG4gICAgfSk7XG4gICAgcmV0dXJuIFByb21pc2UuYWxsKFtcbiAgICAgIHVzZXJuYW1lVW5pcXVlbmVzcyxcbiAgICAgIHVzZXJuYW1lQ2FzZUluc2Vuc2l0aXZlSW5kZXgsXG4gICAgICBlbWFpbFVuaXF1ZW5lc3MsXG4gICAgICBlbWFpbENhc2VJbnNlbnNpdGl2ZUluZGV4LFxuICAgICAgcm9sZVVuaXF1ZW5lc3MsXG4gICAgICBhZGFwdGVySW5pdCxcbiAgICAgIGluZGV4UHJvbWlzZSxcbiAgICBdKTtcbiAgfVxuXG4gIHN0YXRpYyBfdmFsaWRhdGVRdWVyeTogKGFueSwgYm9vbGVhbikgPT4gdm9pZDtcbn1cblxubW9kdWxlLmV4cG9ydHMgPSBEYXRhYmFzZUNvbnRyb2xsZXI7XG4vLyBFeHBvc2UgdmFsaWRhdGVRdWVyeSBmb3IgdGVzdHNcbm1vZHVsZS5leHBvcnRzLl92YWxpZGF0ZVF1ZXJ5ID0gdmFsaWRhdGVRdWVyeTtcbiJdfQ==