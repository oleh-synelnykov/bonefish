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

#ifndef BONEFISH_MESSAGES_WAMP_AUTHENTICATE_EXTRA_HPP
#define BONEFISH_MESSAGES_WAMP_AUTHENTICATE_EXTRA_HPP

#include <msgpack.hpp>
#include <string>
#include <map>

namespace bonefish {

class wamp_authenticate_extra
{
public:
    msgpack::object marshal(msgpack::zone& zone) const;
    void unmarshal(const msgpack::object& details);

    template <typename T>
    T get_extra(const std::string& name) const;

    template <typename T>
    T get_extra_or(const std::string& name, const T& default_value) const;

    template <typename T>
    void set_extra(const std::string& name, const T& value);

private:
    msgpack::zone m_zone;
    std::map<std::string, msgpack::object> m_extra;
};

template <typename T>
T wamp_authenticate_extra::get_extra(const std::string& name) const
{
    const auto extra_itr = m_extra.find(name);
    if (extra_itr == m_extra.end()) {
        throw std::invalid_argument("invalid detail requested: " + name);
    }

    return extra_itr->second.as<T>();
}

template <typename T>
T wamp_authenticate_extra::get_extra_or(const std::string& name, const T& default_value) const
{
    const auto extra_itr = m_extra.find(name);
    if (extra_itr == m_extra.end()) {
        return default_value;
    }

    return extra_itr->second.as<T>();
}

template <typename T>
void wamp_authenticate_extra::set_extra(const std::string& name, const T& value)
{
    m_extra[name] = msgpack::object(value, m_zone);
}

} // namespace bonefish

#endif // BONEFISH_MESSAGES_WAMP_AUTHENTICATE_EXTRA_HPP
