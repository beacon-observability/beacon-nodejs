function setLoose(object, key, value) {
  object[key] = value;
  return value;
}
function setStrict(object, key, value) {
  'use strict';
  object[key] = value;
  return value;
}
function deleteLoose(object, key) {
  return delete object[key];
}
function deleteStrict(object, key) {
  'use strict';
  return delete object[key];
}
module.exports = { setLoose, setStrict, deleteLoose, deleteStrict };
