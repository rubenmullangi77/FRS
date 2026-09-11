#pragma once

#include <iostream>
#include <string>
#include <vector>
#include <functional>
#include <chrono>
#include <cmath>
#include <sstream>

namespace forensivault::testing {

struct TestFailure {
    std::string condition;
    std::string message;
    std::string file;
    int line;
};

class TestCase {
public:
    TestCase(std::string suiteName, std::string testName, std::function<void()> func)
        : suiteName_(std::move(suiteName)), testName_(std::move(testName)), func_(std::move(func)) {}

    void run() {
        failures_.clear();
        try {
            func_();
        } catch (const std::exception& e) {
            recordFailure("Exception", e.what(), __FILE__, __LINE__);
        } catch (...) {
            recordFailure("Unknown", "Unhandled non-std exception", __FILE__, __LINE__);
        }
    }

    void recordFailure(std::string condition, std::string message, std::string file, int line) {
        failures_.push_back({std::move(condition), std::move(message), std::move(file), line});
    }

    [[nodiscard]] const std::string& suiteName() const { return suiteName_; }
    [[nodiscard]] const std::string& testName() const { return testName_; }
    [[nodiscard]] bool passed() const { return failures_.empty(); }
    [[nodiscard]] const std::vector<TestFailure>& failures() const { return failures_; }

private:
    std::string suiteName_;
    std::string testName_;
    std::function<void()> func_;
    std::vector<TestFailure> failures_;
};

class TestRegistry {
public:
    static TestRegistry& getInstance() {
        static TestRegistry instance;
        return instance;
    }

    void registerTest(const std::string& suite, const std::string& name, std::function<void()> func) {
        tests_.emplace_back(suite, name, std::move(func));
    }

    void setCurrentTest(TestCase* test) {
        currentTest_ = test;
    }

    TestCase* currentTest() {
        return currentTest_;
    }

    int runAll() {
        int passed = 0;
        int failed = 0;

        std::cout << "\n============================================================\n";
        std::cout << "        ForensiVault Automated Forensic Test Suite          \n";
        std::cout << "============================================================\n\n";

        auto start = std::chrono::high_resolution_clock::now();

        for (auto& test : tests_) {
            setCurrentTest(&test);
            std::cout << "[ RUN      ] " << test.suiteName() << "." << test.testName() << std::endl;
            
            test.run();

            if (test.passed()) {
                std::cout << "\033[32m[       OK ]\033[0m " << test.suiteName() << "." << test.testName() << std::endl;
                passed++;
            } else {
                std::cout << "\033[31m[  FAILED  ]\033[0m " << test.suiteName() << "." << test.testName() << std::endl;
                for (const auto& f : test.failures()) {
                    std::cout << "  --> " << f.file << ":" << f.line << " | " << f.condition;
                    if (!f.message.empty()) {
                        std::cout << " (" << f.message << ")";
                    }
                    std::cout << "\n";
                }
                failed++;
            }
        }

        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::high_resolution_clock::now() - start).count();

        std::cout << "\n============================================================\n";
        std::cout << " Test Summary: " << (passed + failed) << " total | "
                  << "\033[32m" << passed << " passed\033[0m | "
                  << (failed > 0 ? "\033[31m" : "\033[32m") << failed << " failed\033[0m"
                  << " | " << elapsed << " ms\n";
        std::cout << "============================================================\n\n";

        return failed == 0 ? 0 : 1;
    }

private:
    TestRegistry() = default;
    std::vector<TestCase> tests_;
    TestCase* currentTest_{nullptr};
};

struct TestAutoRegistrar {
    TestAutoRegistrar(const std::string& suite, const std::string& name, std::function<void()> func) {
        TestRegistry::getInstance().registerTest(suite, name, std::move(func));
    }
};

} // namespace forensivault::testing

#define FV_TEST(suite, name) \
    static void _fv_test_##suite##_##name(); \
    static const ::forensivault::testing::TestAutoRegistrar _fv_reg_##suite##_##name( \
        #suite, #name, &_fv_test_##suite##_##name); \
    static void _fv_test_##suite##_##name()

#define ASSERT_TRUE(expr) \
    do { \
        if (!(expr)) { \
            auto* curr = ::forensivault::testing::TestRegistry::getInstance().currentTest(); \
            if (curr) curr->recordFailure(#expr, "Expected true, got false", __FILE__, __LINE__); \
            return; \
        } \
    } while (0)

#define ASSERT_FALSE(expr) \
    do { \
        if (expr) { \
            auto* curr = ::forensivault::testing::TestRegistry::getInstance().currentTest(); \
            if (curr) curr->recordFailure(#expr, "Expected false, got true", __FILE__, __LINE__); \
            return; \
        } \
    } while (0)

#define ASSERT_EQ(val1, val2) \
    do { \
        if ((val1) != (val2)) { \
            std::ostringstream ss; \
            ss << "Expected " << (val1) << " == " << (val2); \
            auto* curr = ::forensivault::testing::TestRegistry::getInstance().currentTest(); \
            if (curr) curr->recordFailure(#val1 " == " #val2, ss.str(), __FILE__, __LINE__); \
            return; \
        } \
    } while (0)

#define ASSERT_NE(val1, val2) \
    do { \
        if ((val1) == (val2)) { \
            std::ostringstream ss; \
            ss << "Expected " << (val1) << " != " << (val2); \
            auto* curr = ::forensivault::testing::TestRegistry::getInstance().currentTest(); \
            if (curr) curr->recordFailure(#val1 " != " #val2, ss.str(), __FILE__, __LINE__); \
            return; \
        } \
    } while (0)

#define ASSERT_NEAR(val1, val2, epsilon) \
    do { \
        if (std::abs((val1) - (val2)) > (epsilon)) { \
            std::ostringstream ss; \
            ss << "Expected |" << (val1) << " - " << (val2) << "| <= " << (epsilon); \
            auto* curr = ::forensivault::testing::TestRegistry::getInstance().currentTest(); \
            if (curr) curr->recordFailure(#val1 " near " #val2, ss.str(), __FILE__, __LINE__); \
            return; \
        } \
    } while (0)
