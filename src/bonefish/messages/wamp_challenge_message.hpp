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

#ifndef BONEFISH_MESSAGES_WAMP_CHALLENGE_MESSAGE_HPP
#define BONEFISH_MESSAGES_WAMP_CHALLENGE_MESSAGE_HPP

#include <bonefish/messages/wamp_message.hpp>

#include <cassert>
#include <msgpack.hpp>
#include <ostream>
#include <string>

namespace bonefish {

//
// [CHALLENGE, AuthMethod|string, Extra|dict]
//
class wamp_challenge_message : public wamp_message
{
public:
    wamp_challenge_message();
    wamp_challenge_message(msgpack::zone&& zone);
    virtual ~wamp_challenge_message() override;

    virtual wamp_message_type get_type() const override;
    virtual std::vector<msgpack::object> marshal() const override;
    virtual void unmarshal(
            const std::vector<msgpack::object>& fields,
            msgpack::zone&& zone) override;

    std::string get_auth_method() const;
    const msgpack::object& get_extra() const;

    void set_auth_method(const std::string& method);
    void set_extra(const msgpack::object& extra);

private:
    msgpack::object m_type;
    msgpack::object m_auth_method;
    msgpack::object m_extra;

private:
    static const size_t NUM_FIELDS = 3;
};

inline wamp_challenge_message::wamp_challenge_message()
    : wamp_challenge_message(msgpack::zone())
{
}

inline wamp_challenge_message::wamp_challenge_message(msgpack::zone&& zone)
    : wamp_message(std::move(zone))
    , m_type(wamp_message_type::CHALLENGE)
    , m_auth_method()
    , m_extra(msgpack_empty_map())
{
}

inline wamp_challenge_message::~wamp_challenge_message()
{
}

inline wamp_message_type wamp_challenge_message::get_type() const
{
    return m_type.as<wamp_message_type>();
}

inline std::vector<msgpack::object> wamp_challenge_message::marshal() const
{
    std::vector<msgpack::object> fields { m_type, m_auth_method, m_extra };
    return fields;
}

inline void wamp_challenge_message::unmarshal(
        const std::vector<msgpack::object>& fields,
        msgpack::zone&& zone)
{
    if (fields.size() != NUM_FIELDS) {
        throw std::invalid_argument("invalid number of fields");
    }

    if (fields[0].as<wamp_message_type>() != get_type()) {
        throw std::invalid_argument("invalid message type");
    }

    acquire_zone(std::move(zone));
    m_auth_method = fields[1];
    m_extra = fields[2];
}

inline std::string wamp_challenge_message::get_auth_method() const
{
    return m_auth_method.as<std::string>();
}

inline const msgpack::object& wamp_challenge_message::get_extra() const
{
    return m_extra;
}

inline void wamp_challenge_message::set_auth_method(const std::string& realm)
{
    m_auth_method = msgpack::object(realm, get_zone());
}

inline void wamp_challenge_message::set_extra(const msgpack::object& extra)
{
    assert(extra.type == msgpack::type::MAP);
    m_extra = msgpack::object(extra, get_zone());
}

inline std::ostream& operator<<(std::ostream& os, const wamp_challenge_message& message)
{
    os << "challenge [" << message.get_auth_method() << ", "
            << message.get_extra() << "]";
    return os;
}

} // namespace bonefish

#endif // BONEFISH_MESSAGES_WAMP_CHALLENGE_MESSAGE_HPP
