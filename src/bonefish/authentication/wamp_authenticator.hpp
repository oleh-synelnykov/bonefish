/**
 *  Copyright (C) 2022 Vizio Services
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

#ifndef BONEFISH_WAMP_AUTHENTICATOR_HPP
#define BONEFISH_WAMP_AUTHENTICATOR_HPP

#include <bonefish/authentication/wamp_authentication_info.hpp>
#include <bonefish/messages/wamp_authenticate_extra.hpp>
#include <bonefish/messages/wamp_challenge_extra.hpp>

#include <functional>
#include <map>
#include <memory>
#include <optional>

namespace bonefish {

class wamp_challenge_message;
class wamp_welcome_message;

class wamp_authenticator
{
public:
    struct auth_type {
        static constexpr auto anonymous = "anonymous";
        static constexpr auto ticket = "ticket";
        static constexpr auto cra = "wampcra";
        static constexpr auto cyrptosign = "cryptosign";
        static constexpr auto scram = "scram";
    };

    struct challenge {
        wamp_authentication_info auth;
        wamp_challenge_extra extra;
    };

    struct authentication_request {
        std::string signature;
        wamp_authentication_info auth;
        wamp_authenticate_extra extra;
    };

    struct authentication_result {
        wamp_authenticate_extra extra;
    };

public:
    virtual std::vector<std::string> methods() const = 0;

    virtual std::optional<challenge> generate_challenge(
            const std::string& auth_id,
            const std::string& method) = 0;

    virtual std::optional<authentication_result> authenticate(
            const authentication_request& request) = 0;
};

}  // namespace bonefish

#endif  // BONEFISH_WAMP_AUTHENTICATOR_HPP
