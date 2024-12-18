// i want to create a function that takes a string and a key and returns the encrypted string. And then send it to the server using both the get and post methods. Use any http library to do this.

#include <iostream>
#include <string>
#include <curl/curl.h>

std::string encrypt(const std::string& str, const std::string& key) {
    std::string encrypted = str;
    for (size_t i = 0; i < str.size(); ++i) {
        encrypted[i] = str[i] ^ key[i % key.size()];
    }
    return encrypted;
}

int send_get_request(const std::string& url) {
    CURL *curl;
    CURLcode res;
    curl = curl_easy_init();
    if(curl) {
        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        res = curl_easy_perform(curl);
        curl_easy_cleanup(curl);
    }
    return res;
}

int main() {
    std::string url = "http://localhost:8080/";
    send_get_request(url);
    return 0;
}






