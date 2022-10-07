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

#include <bonefish/messages/wamp_hello_details_advanced.hpp>

#include <stdexcept>

namespace bonefish {

msgpack::object wamp_hello_details_advanced::marshal(msgpack::zone& zone) const
{
    throw std::logic_error("marshal not implemented");
}

void wamp_hello_details_advanced::unmarshal(const msgpack::object& object)
{
    std::unordered_map<std::string, msgpack::object> details;
    object.convert(details);

    auto details_itr = details.find("authid");
    if (details_itr == details.end()) {
        return;
    }

    details_itr->second.convert(m_auth_id);

    details_itr = details.find("authmethods");
    if (details_itr == details.end()) {
        return;
    }

    details_itr->second.convert(m_auth_methods);
}

} // namespace bonefish
