import Cookies from "js-cookie";
import jwtDecode from "jwt-decode";
import moment from "moment";
import "moment-duration-format";
import XLSX from "xlsx";
// Export the calculateTimeGap function with maxGap parameter
export function calculateTimeGap(date1, date2, maxGap) {
  const momentDate1 = moment(date1, "YYYY-MM-DD HH:mm:ss");
  const momentDate2 = date2 ? moment(date2, "YYYY-MM-DD HH:mm:ss") : moment();

  // Calculate the time gap duration
  const duration = moment.duration(momentDate2.diff(momentDate1));

  // Calculate the years and months in the duration
  const years = duration.years();
  const months = duration.months();

  // Check if the duration exceeds the maximum allowable time gap in months
  if (duration.asMonths() > maxGap) {
    return `Time Gap exceeds the maximum allowable (${maxGap} months)`;
  }

  // Format the duration based on the maxGap value
  let formattedDuration = "";
  if (years > 0) {
    formattedDuration += `${years} year${years > 1 ? "s" : ""}`;
  }
  if (months > 0) {
    if (formattedDuration) {
      formattedDuration += " ";
    }
    formattedDuration += `${months} month${months > 1 ? "s" : ""}`;
  }

  return `${formattedDuration}`;
}

export const formatFileSize = (bytes) => {
  if (bytes === 0) return "0 Bytes";

  const k = 1024;
  const sizes = ["Bytes", "KB", "MB", "GB", "TB"];
  const i = Math.floor(Math.log(bytes) / Math.log(k));

  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + " " + sizes[i];
};


export const findIndex = (array, index) => {
  const found = array.find(function (element, ind) {
    return index === ind;
  });
  return found
};


export const arrayGroupbykey = (array, key) => {

  // @ts-ignore
  const uniqueCategories = [...new Set(array.map(item => item[key]))];

  // Create a function to filter the array based on a category
  function filterByCategory(array, key) {
    return array.filter(item => item.category === key);
  }

  // Create an array to store filtered arrays
  const filteredArrays = [];

  // Filter the array for each unique category and push the results into the filteredArrays array
  uniqueCategories.forEach(key => {
    const filteredArray = filterByCategory(array, key);
    filteredArrays.push(filteredArray);
  });

  return filteredArrays
}






export const setToken = (name, value, days, type) => {
  if (type === "ACCESS_TOKEN") {
    const token = value.split(".");
    setClientCookie("headerPayload", `${token[0]}.${token[1]}`, days);
    setClientCookie("signature", `${token[2]}`, days);
  } else {
    setClientCookie(name, value, days);
  }
};

export const setClientCookie = (name, value, timestamp) => {
  const expirationDate = new Date(timestamp * 1000); // Convert Unix timestamp to milliseconds
  Cookies.set(name, value, { expires: expirationDate });
};


export const saveCookies = (res) => {
  const token = res["access_token"].split(".");
  setToken("headerPayload", `${token[0]}.${token[1]}`, res["exp"]);
  setToken("signature", `${token[2]}`, res["exp"]);

  const access_token = jwtDecode(res["access_token"]);
  const userInfo = jwtDecode(res["id_token"]);
  const currObj = {
    refreshToken: res["refresh_token"],
    idToken: res["id_token"], id: access_token["user_id"], email: userInfo["email"], image: userInfo["profilePicture"], name: `${userInfo["firstName"]} ${userInfo["lastName"]}`
  }
  storeCookiesOfObject({ ...res, ...currObj })

  return {userInfo,access_token}
}





export function generateUrlFromNestedObject(nestedObject) {
  const queryParams = [];

  const processNestedObject = (obj, prefix = '') => {
    for (const key in obj) {
      if (obj.hasOwnProperty(key)) {
        const value = obj[key];

        if (typeof value === 'object' && value !== null) {
          processNestedObject(value, prefix + key + '.');
        } else {
          queryParams.push(`${encodeURIComponent(prefix + key)}=${encodeURIComponent(value)}`);
        }
      }
    }
  };

  processNestedObject(nestedObject);

  if (queryParams.length > 0) {
    return '?' + queryParams.join('&');
  } else {
    return '';
  }
}

export function parseUrlWithQueryParams(url) {
  const queryString = url.split('?')[1];
  if (!queryString) {
    return {};
  }

  const params = new URLSearchParams(queryString);
  const nestedObject = {};

  params.forEach((value, key) => {
    const keys = key.split('.');
    let currentLevel = nestedObject;

    for (let i = 0; i < keys.length - 1; i++) {
      currentLevel[keys[i]] = currentLevel[keys[i]] || {};
      currentLevel = currentLevel[keys[i]];
    }

    // Check for empty or undefined values before decoding
    const decodedValue = value === 'undefined' ? undefined : decodeURIComponent(value);
    currentLevel[keys[keys.length - 1]] = decodedValue;
  });

  return nestedObject;
}

export function storeCookiesOfObject(data) {
  if (data) {
    const userKeys = Object.keys(data);

    userKeys.forEach(key => {
      const value = data[key];
      Cookies.set(key, value);
    });
  }
}


export const exportData = (data, filename) => {
  const worksheet = XLSX.utils.json_to_sheet(data);
  const workbook = XLSX.utils.book_new();
  XLSX.utils.book_append_sheet(workbook, worksheet, "Sheet1");

  return XLSX.writeFile(workbook, `${filename}_${Date.now()}.xlsx`);
};


export const exportExcelFile = (data, columnobj, filename) => {

  var xlsdata = [];

  xlsdata = data.map(item => {
    const newItem = {};
    for (const key in columnobj) {
      newItem[columnobj[key]] = item[key];
    }
    return newItem;
  });


  exportData(xlsdata, filename);

}
export function arraySumByKey(array, key) {
  return array.reduce((accumulator, currentValue) => {
      return accumulator + currentValue[key];
  }, 0);
}