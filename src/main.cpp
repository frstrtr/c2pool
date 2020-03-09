#include <ctime>
#include <iostream>
#include <string>
#include <boost/bind.hpp>
#include <boost/shared_ptr.hpp>
#include <boost/enable_shared_from_this.hpp>
#include <boost/asio.hpp>
#include <boost/asio/buffer.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/read_until.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/write.hpp>

using boost::asio::ip::tcp;
using boost::asio::steady_timer;

class client
{
public:
    client(boost::asio::io_context& io_context)
            : stopped_(false),
              socket_(io_context),
              deadline_(io_context),
              heartbeat_timer_(io_context)
    {
    }

    // Called by the user of the client class to initiate the connection process.
    // The endpoints will have been obtained using a tcp::resolver.
    void start(tcp::resolver::results_type endpoints)
    {
        // Start the connect actor.
        endpoints_ = endpoints;
        start_connect(endpoints_.begin());

        // Start the deadline actor. You will note that we're not setting any
        // particular deadline here. Instead, the connect and input actors will
        // update the deadline prior to each asynchronous operation.
        deadline_.async_wait(boost::bind(&client::check_deadline, this));
    }

    // This function terminates all the actors to shut down the connection. It
    // may be called by the user of the client class, or by the class itself in
    // response to graceful termination or an unrecoverable error.
    void stop()
    {
        stopped_ = true;
        boost::system::error_code ignored_ec;
        socket_.close(ignored_ec);
        deadline_.cancel();
        heartbeat_timer_.cancel();
    }

private:
    void start_connect(tcp::resolver::results_type::iterator endpoint_iter)
    {
        if (endpoint_iter != endpoints_.end())
        {
            std::cout << "Trying " << endpoint_iter->endpoint() << "...\n";

            // Set a deadline for the connect operation.
            deadline_.expires_after(boost::asio::chrono::seconds(60));

            // Start the asynchronous connect operation.
            socket_.async_connect(endpoint_iter->endpoint(),
                                  boost::bind(&client::handle_connect,
                                              this, _1, endpoint_iter));
        }
        else
        {
            // There are no more endpoints to try. Shut down the client.
            stop();
        }
    }

    void handle_connect(const boost::system::error_code& ec,
                        tcp::resolver::results_type::iterator endpoint_iter)
    {
        if (stopped_)
            return;

        // The async_connect() function automatically opens the socket at the start
        // of the asynchronous operation. If the socket is closed at this time then
        // the timeout handler must have run first.
        if (!socket_.is_open())
        {
            std::cout << "Connect timed out\n";

            // Try the next available endpoint.
            start_connect(++endpoint_iter);
        }

            // Check if the connect operation failed before the deadline expired.
        else if (ec)
        {
            std::cout << "Connect error: " << ec.message() << "\n";

            // We need to close the socket used in the previous connection attempt
            // before starting a new one.
            socket_.close();

            // Try the next available endpoint.
            start_connect(++endpoint_iter);
        }

            // Otherwise we have successfully established a connection.
        else
        {
            std::cout << "Connected to " << endpoint_iter->endpoint() << "\n";

            // Start the input actor.
            start_read();

            // Start the heartbeat actor.
            start_write();
        }
    }

    void start_read()
    {
        // Set a deadline for the read operation.
        deadline_.expires_after(boost::asio::chrono::seconds(30));

        // Start an asynchronous operation to read a newline-delimited message.
        boost::asio::async_read_until(socket_,
                                      boost::asio::dynamic_buffer(input_buffer_), '\n',
                                      boost::bind(&client::handle_read, this, _1, _2));
    }

    void handle_read(const boost::system::error_code& ec, std::size_t n)
    {
        if (stopped_)
            return;

        if (!ec)
        {
            // Extract the newline-delimited message from the buffer.
            std::string line(input_buffer_.substr(0, n - 1));
            input_buffer_.erase(0, n);

            // Empty messages are heartbeats and so ignored.
            if (!line.empty())
            {
                std::cout << "Received: " << line << "\n";
            }

            start_read();
        }
        else
        {
            std::cout << "Error on receive: " << ec.message() << "\n";

            stop();
        }
    }

    void start_write()
    {
        if (stopped_)
            return;

        // Start an asynchronous operation to send a heartbeat message.
        boost::asio::async_write(socket_, boost::asio::buffer("\n", 1),
                                 boost::bind(&client::handle_write, this, _1));
    }

    void handle_write(const boost::system::error_code& ec)
    {
        if (stopped_)
            return;

        if (!ec)
        {
            // Wait 10 seconds before sending the next heartbeat.
            heartbeat_timer_.expires_after(boost::asio::chrono::seconds(10));
            heartbeat_timer_.async_wait(boost::bind(&client::start_write, this));
        }
        else
        {
            std::cout << "Error on heartbeat: " << ec.message() << "\n";

            stop();
        }
    }

    void check_deadline()
    {
        if (stopped_)
            return;

        // Check whether the deadline has passed. We compare the deadline against
        // the current time since a new asynchronous operation may have moved the
        // deadline before this actor had a chance to run.
        if (deadline_.expiry() <= steady_timer::clock_type::now())
        {
            // The deadline has passed. The socket is closed so that any outstanding
            // asynchronous operations are cancelled.
            socket_.close();

            // There is no longer an active deadline. The expiry is set to the
            // maximum time point so that the actor takes no action until a new
            // deadline is set.
            deadline_.expires_at(steady_timer::time_point::max());
        }

        // Put the actor back to sleep.
        deadline_.async_wait(boost::bind(&client::check_deadline, this));
    }

private:
    bool stopped_;
    tcp::resolver::results_type endpoints_;
    tcp::socket socket_;
    std::string input_buffer_;
    steady_timer deadline_;
    steady_timer heartbeat_timer_;
};


std::string make_daytime_string()
{
    using namespace std; // For time_t, time and ctime;
    time_t now = time(0);
    return ctime(&now);
}

class tcp_connection:public boost::enable_shared_from_this<tcp_connection>
{
public:
    typedef boost::shared_ptr<tcp_connection> pointer;

    static pointer create(boost::asio::io_context& io_context)
    {
        return pointer(new tcp_connection(io_context));
    }

    tcp::socket& socket()
    {
        return socket_;
    }

    void start() {
        message_ =  boost::asio::ip::host_name() +" _____ "+ socket_.remote_endpoint().address().to_string() + "________" + socket_.local_endpoint().address().to_string() + " _____ " + make_daytime_string() ;

        boost::asio::async_write(socket_, boost::asio::buffer(message_),
                                 boost::bind(&tcp_connection::handle_write, shared_from_this(),
                                             boost::asio::placeholders::error,
                                             boost::asio::placeholders::bytes_transferred));
    }

private:
    tcp::socket socket_;
    std::string message_;

    tcp_connection(boost::asio::io_context& io_context): socket_(io_context)
    {
    }

    void handle_write(const boost::system::error_code& /*error*/, size_t /*bytes_transferred*/)
    {
    }


};

class tcp_server {
public:
    tcp_server(boost::asio::io_context &io_context) : io_context_(io_context), acceptor_(io_context, tcp::endpoint(tcp::v4(), 13)) {
        start_accept();
    }

private:
    void start_accept() {
        tcp_connection::pointer new_connection = tcp_connection::create(io_context_);

        acceptor_.async_accept(new_connection->socket(),boost::bind(&tcp_server::handle_accept, this, new_connection, boost::asio::placeholders::error));
    }

    void handle_accept(tcp_connection::pointer new_connection, const boost::system::error_code &error) {
        if (!error) {
            new_connection->start();
        }

        start_accept();
    }

    boost::asio::io_context &io_context_;
    tcp::acceptor acceptor_;
};

int main(int argc, char* argv[])
{
    setlocale(LC_ALL,"Russian");
    try
    {
        boost::asio::io_context io_context;
        tcp_server server(io_context);

        char* host = "127.0.0.1";
        char* port = "13";


        tcp::resolver r(io_context);
        client c(io_context);

        c.start(r.resolve(host, port));


        io_context.run();
    }
    catch (std::exception& e)
    {
        std::cerr << "Exception: " << e.what() << "\n";
    }

    return 0;
}