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

#ifndef BONEFISH_MESSAGES_WAMP_AUTHENTICATE_MESSAGE_HPP
#define BONEFISH_MESSAGES_WAMP_AUTHENTICATE_MESSAGE_HPP

#include <bonefish/messages/wamp_message.hpp>
#include <bonefish/messages/wamp_message_defaults.hpp>
#include <bonefish/utility/wamp_uri.hpp>

#include <cassert>
#include <cstddef>
#include <msgpack.hpp>
#include <ostream>
#include <string>
#include <vector>

namespace bonefish {

//
// [AUTHENTICATE, Signature|string, Extra|dict]
//
class wamp_authenticate_message : public wamp_message
{
public:
    wamp_authenticate_message();
    wamp_authenticate_message(msgpack::zone&& zone);
    virtual ~wamp_authenticate_message() override;

    virtual wamp_message_type get_type() const override;
    virtual std::vector<msgpack::object> marshal() const override;
    virtual void unmarshal(
            const std::vector<msgpack::object>& fields,
            msgpack::zone&& zone) override;

    std::string get_signature() const;
    const msgpack::object& get_extra() const;

    void set_signature(const std::string& signature);
    void set_extra(const msgpack::object& extra);

private:
    msgpack::object m_type;
    msgpack::object m_signature;
    msgpack::object m_extra;

private:
    static const size_t NUM_FIELDS = 3;
};

inline wamp_authenticate_message::wamp_authenticate_message()
    : wamp_authenticate_message(msgpack::zone())
{
}

inline wamp_authenticate_message::wamp_authenticate_message(msgpack::zone&& zone)
    : wamp_message(std::move(zone))
    , m_type(wamp_message_type::AUTHENTICATE)
    , m_signature()
    , m_extra(msgpack_empty_map())
{
}

inline wamp_authenticate_message::~wamp_authenticate_message()
{
}

inline wamp_message_type wamp_authenticate_message::get_type() const
{
    return m_type.as<wamp_message_type>();
}

inline std::vector<msgpack::object> wamp_authenticate_message::marshal() const
{
    std::vector<msgpack::object> fields { m_type, m_signature, m_extra };
    return fields;
}

inline void wamp_authenticate_message::unmarshal(
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
    m_signature = fields[1];
    m_extra = fields[2];
}

inline std::string wamp_authenticate_message::get_signature() const
{
    return m_signature.as<std::string>();
}

inline const msgpack::object& wamp_authenticate_message::get_extra() const
{
    return m_extra;
}

inline void wamp_authenticate_message::set_signature(const std::string& signature)
{
    m_signature = msgpack::object(signature, get_zone());
}

inline void wamp_authenticate_message::set_extra(const msgpack::object& extra)
{
    assert(details.type == msgpack::type::MAP);
    m_extra = msgpack::object(extra, get_zone());
}

inline std::ostream& operator<<(std::ostream& os, const wamp_authenticate_message& message)
{
    os << "authenticate [" << message.get_signature() << ", "
            << message.get_extra() << "]";
    return os;
}

} // namespace bonefish


#endif // BONEFISH_MESSAGES_WAMP_AUTHENTICATE_MESSAGE_HPP
