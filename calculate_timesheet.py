from datetime import datetime, timedelta
import time


def parse_time(time_str):
    print(datetime.strptime(time_str.strip(), "%H:%M").time())
    return datetime.strptime(time_str.strip(), "%H:%M").time()


def calculate_total_presence(times):
    total_time = timedelta()  # جمع زمان‌ها (نوع timedelta)

    # فرض اینکه times به فرمت "9:31, 17:19, ..." باشد و مقادیر به صورت جفت جفت بیایند
    time_list = times.split(",")  # جدا کردن ساعت‌ها

    # حلقه‌ای برای محاسبه اختلاف ورود و خروج به صورت جفت جفت
    for i in range(0, len(time_list), 2):
        if i + 1 < len(time_list):
            entry_time = parse_time(time_list[i])  # زمان ورود

            exit_time = parse_time(time_list[i + 1])  # زمان خروج

            # تبدیل به datetime برای محاسبه اختلاف
            entry_datetime = datetime.combine(datetime.today(), entry_time)

            exit_datetime = datetime.combine(datetime.today(), exit_time)

            # جمع زمان‌ها
            total_time += (exit_datetime - entry_datetime)

    # برگرداندن مجموع زمان حضور به صورت دقیقه یا ساعت
    total_seconds = int(total_time.total_seconds())  # کل ثانیه‌ها
    hours, remainder = divmod(total_seconds, 3600)  # استخراج ساعت
    minutes, seconds = divmod(remainder, 60)  # استخراج دقیقه و ثانیه

    # برگرداندن مجموع زمان حضور به صورت h:m:s
    return f"{hours:02}:{minutes:02}:{seconds:02}"
    # return total_time.total_seconds() / 3600  # تبدیل به ساعت