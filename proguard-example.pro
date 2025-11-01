# Example ProGuard Configuration for Strong Obfuscation
# Use this as a reference for improving your obfuscation score

# Basic obfuscation settings
-dontskipnonpubliclibraryclasses
-verbose

# Optimization passes
-optimizationpasses 5
-optimizations !code/simplification/arithmetic,!field/*,!class/merging/*

# Aggressive name obfuscation
-repackageclasses ''
-allowaccessmodification
-overloadaggressively

# Keep class members
-keepattributes *Annotation*
-keep public class * extends android.app.Activity
-keep public class * extends android.app.Application
-keep public class * extends android.app.Service
-keep public class * extends android.content.BroadcastReceiver
-keep public class * extends android.content.ContentProvider

# Keep native methods
-keepclasseswithmembernames class * {
    native <methods>;
}

# Keep view constructors (for XML inflation)
-keepclasseswithmembers class * {
    public <init>(android.content.Context, android.util.AttributeSet);
}

-keepclasseswithmembers class * {
    public <init>(android.content.Context, android.util.AttributeSet, int);
}

# Keep Activity method parameters
-keepclassmembers class * extends android.app.Activity {
    public void *(android.view.View);
}

# Keep enum values
-keepclassmembers enum * {
    public static **[] values();
    public static ** valueOf(java.lang.String);
}

# Keep Parcelable
-keepclassmembers class * implements android.os.Parcelable {
    public static final android.os.Parcelable$Creator CREATOR;
}

# Keep Serializable
-keepclassmembers class * implements java.io.Serializable {
    static final long serialVersionUID;
    private static final java.io.ObjectStreamField[] serialPersistentFields;
    private void writeObject(java.io.ObjectOutputStream);
    private void readObject(java.io.ObjectInputStream);
    java.lang.Object writeReplace();
    java.lang.Object readResolve();
}

# R8 Full Mode (more aggressive)
-allowaccessmodification
-repackageclasses

# Remove logging (optional, but reduces attack surface)
-assumenosideeffects class android.util.Log {
    public static *** d(...);
    public static *** v(...);
    public static *** i(...);
}

# Obfuscate specific packages (adjust to your app)
# -keep class com.yourapp.model.** { *; }  # Keep data models
# -keep class com.yourapp.api.** { *; }    # Keep API interfaces

# For DexGuard users (commercial):
# -encryptstrings class com.yourapp.** {
#     private static final java.lang.String *;
# }
# -obfuscatecontrolflow class com.yourapp.** {
#     public *;
# }

# Notes:
# 1. Test thoroughly after enabling aggressive obfuscation
# 2. Add -keep rules for libraries that use reflection
# 3. Check mapping.txt to verify obfuscation worked
# 4. Use this analyzer to measure effectiveness
