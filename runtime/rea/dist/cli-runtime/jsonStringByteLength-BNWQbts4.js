import { __esmMin } from "./rolldown-runtime-DXoylpqc.js";

//#region dist/domain/jsonStringByteLength.js
var jsonStringByteLength;
function init_jsonStringByteLength() {
	return (init_jsonStringByteLength = __esmMin((() => {
		jsonStringByteLength = (value, budget = Number.POSITIVE_INFINITY) => {
			let bytes = 2;
			for (let index = 0; index < value.length && bytes <= budget; index++) {
				const unit = value.charCodeAt(index);
				if (unit === 34 || unit === 92) bytes += 2;
				else if (unit < 32) bytes += unit === 8 || unit === 9 || unit === 10 || unit === 12 || unit === 13 ? 2 : 6;
				else if (unit < 128) bytes += 1;
				else if (unit < 2048) bytes += 2;
				else if (unit >= 55296 && unit <= 56319) {
					const next = value.charCodeAt(index + 1);
					if (next >= 56320 && next <= 57343) {
						bytes += 4;
						index++;
					} else bytes += 6;
				} else if (unit >= 56320 && unit <= 57343) bytes += 6;
				else bytes += 3;
			}
			return bytes;
		};
	})))();
}

//#endregion
export { init_jsonStringByteLength, jsonStringByteLength };