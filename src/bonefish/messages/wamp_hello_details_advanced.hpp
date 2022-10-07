/**
 *  Copyright (C) 2015 Topology LP
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

#ifndef BONEFISH_MESSAGES_WAMP_HELLO_DETAILS_ADVANCED_HPP
#define BONEFISH_MESSAGES_WAMP_HELLO_DETAILS_ADVANCED_HPP

#include <msgpack.hpp>
#include <string>
#include <vector>

namespace bonefish {

class wamp_hello_details_advanced
{
public:
    msgpack::object marshal(msgpack::zone& zone) const;
    void unmarshal(const msgpack::object& details);

    const std::string& get_auth_id() const;

    const std::vector<std::string>& get_auth_methods() const;

private:
    std::string m_auth_id;
    std::vector<std::string> m_auth_methods;
};

inline const std::string& wamp_hello_details_advanced::get_auth_id() const
{
    return m_auth_id;
}

inline const std::vector<std::string>&
wamp_hello_details_advanced::get_auth_methods() const
{
    return m_auth_methods;
}

} // namespace bonefish

#endif // BONEFISH_MESSAGES_WAMP_HELLO_DETAILS_HPP
