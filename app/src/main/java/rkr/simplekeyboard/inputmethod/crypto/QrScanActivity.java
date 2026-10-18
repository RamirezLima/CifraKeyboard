/*
 * Copyright (C) 2026 Ramirez Lima
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package rkr.simplekeyboard.inputmethod.crypto;

import android.Manifest;
import android.app.Activity;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.graphics.ImageFormat;
import android.graphics.Matrix;
import android.graphics.RectF;
import android.graphics.SurfaceTexture;
import android.hardware.camera2.CameraAccessException;
import android.hardware.camera2.CameraCaptureSession;
import android.hardware.camera2.CameraCharacteristics;
import android.hardware.camera2.CameraDevice;
import android.hardware.camera2.CameraManager;
import android.hardware.camera2.CaptureRequest;
import android.hardware.camera2.params.StreamConfigurationMap;
import android.media.Image;
import android.media.ImageReader;
import android.os.Bundle;
import android.os.Handler;
import android.os.HandlerThread;
import android.util.Log;
import android.util.Size;
import android.util.SparseArray;
import android.view.Surface;
import android.view.TextureView;
import android.view.WindowManager;
import android.widget.TextView;

import com.google.zxing.PlanarYUVLuminanceSource;

import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;

import rkr.simplekeyboard.inputmethod.R;

/**
 * Reads a QR code with the camera and reports what it carried to the caller, which may be the
 * keyboard. Frames are only looked at in memory, one at a time, and never stored; the app has no
 * network permission to send them anywhere.
 *
 * Uses the platform camera API directly, so no camera library is needed.
 */
public final class QrScanActivity extends Activity implements TextureView.SurfaceTextureListener {
    private static final String TAG = QrScanActivity.class.getSimpleName();

    public interface Callback {
        /** @param content what the code carried, or null if the user gave up. */
        void onResult(QrCodes.Content content);
    }

    /** A Cifra message, armored or in its wire format. */
    public static final int KIND_MESSAGE = 1;
    /** A Cifra public key. */
    public static final int KIND_KEY = 2;

    private static final String EXTRA_REQUEST_ID = "cifra_qr_request";
    private static final String EXTRA_KIND = "cifra_qr_kind";
    private static final String EXTRA_HOLDS_KEYS = "cifra_qr_holds_keys";
    private static final int REQUEST_CAMERA = 1;
    /** Larger frames only make decoding slower; a version 20 code is readable well below. */
    private static final int MAX_FRAME_PIXELS = 1920 * 1080;

    private static final SparseArray<Callback> sPending = new SparseArray<>();
    private static int sNextRequestId;

    /**
     * @param kind what to look for: other codes are ignored while the camera keeps looking.
     * @param holdsKeys whether this phone keeps identities, so it should be offline.
     */
    public static void request(final Context context, final int kind, final boolean holdsKeys,
            final Callback callback) {
        final int requestId = ++sNextRequestId;
        sPending.put(requestId, callback);
        final Intent intent = new Intent(context, QrScanActivity.class)
                .putExtra(EXTRA_REQUEST_ID, requestId)
                .putExtra(EXTRA_KIND, kind)
                .putExtra(EXTRA_HOLDS_KEYS, holdsKeys);
        if (!(context instanceof Activity)) {
            // From the keyboard service.
            intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
        }
        try {
            context.startActivity(intent);
        } catch (RuntimeException e) {
            deliver(requestId, null);
        }
    }

    private static void deliver(final int requestId, final QrCodes.Content content) {
        final Callback callback = sPending.get(requestId);
        sPending.remove(requestId);
        if (callback != null) {
            callback.onResult(content);
        }
    }

    private int mRequestId;
    private int mKind;
    private boolean mDelivered;
    private boolean mAskedPermission;
    private TextureView mPreview;
    private TextView mStatus;

    private HandlerThread mCameraThread;
    private Handler mCameraHandler;
    /** Held while the camera opens or closes, so closing never misses a camera being opened. */
    private final Semaphore mOpenCloseLock = new Semaphore(1);
    private volatile CameraDevice mCamera;
    private volatile CameraCaptureSession mSession;
    private volatile ImageReader mFrames;
    private volatile Size mFrameSize;
    private volatile int mSensorOrientation;
    private int mAfMode;
    /** Set once a code is read; later frames are dropped. */
    private volatile boolean mFound;
    /** Camera thread only. */
    private byte[] mLuminance;
    /** Camera thread only: the parts of a message read so far. */
    private final QrCodes.Assembler mAssembler = new QrCodes.Assembler();
    private int mShownParts = -1;

    @Override
    protected void onCreate(final Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        getWindow().addFlags(WindowManager.LayoutParams.FLAG_SECURE
                | WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON);
        mRequestId = getIntent().getIntExtra(EXTRA_REQUEST_ID, -1);
        mKind = getIntent().getIntExtra(EXTRA_KIND, KIND_MESSAGE);
        setContentView(R.layout.cifra_activity_qr_scan);
        QrViews.applyInsets(findViewById(R.id.cifra_qr_panel));
        ((TextView) findViewById(R.id.cifra_qr_title)).setText(mKind == KIND_KEY
                ? R.string.cifra_qr_scan_key_title : R.string.cifra_qr_scan_title);
        QrViews.showOnlineWarning(this, findViewById(R.id.cifra_qr_warning),
                getIntent().getBooleanExtra(EXTRA_HOLDS_KEYS, false));
        mStatus = findViewById(R.id.cifra_qr_status);
        mPreview = findViewById(R.id.cifra_qr_preview);
        mPreview.setSurfaceTextureListener(this);
        findViewById(R.id.cifra_qr_close).setOnClickListener(v -> finish());
    }

    @Override
    protected void onResume() {
        super.onResume();
        if (!hasCameraPermission()) {
            if (!mAskedPermission) {
                mAskedPermission = true;
                requestPermissions(new String[] { Manifest.permission.CAMERA }, REQUEST_CAMERA);
            }
            return;
        }
        mCameraThread = new HandlerThread("CifraQrCamera");
        mCameraThread.start();
        mCameraHandler = new Handler(mCameraThread.getLooper());
        if (mPreview.isAvailable()) {
            openCamera();
        }
    }

    @Override
    protected void onPause() {
        closeCamera();
        if (mCameraThread != null) {
            mCameraThread.quitSafely();
            try {
                mCameraThread.join(1000);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            mCameraThread = null;
            mCameraHandler = null;
        }
        super.onPause();
    }

    @Override
    protected void onDestroy() {
        if (!mDelivered && !isChangingConfigurations()) {
            mDelivered = true;
            deliver(mRequestId, null);
        }
        super.onDestroy();
    }

    @Override
    public void onRequestPermissionsResult(final int requestCode, final String[] permissions,
            final int[] grantResults) {
        if (requestCode == REQUEST_CAMERA && !hasCameraPermission()) {
            mStatus.setText(R.string.cifra_qr_no_camera);
        }
    }

    private boolean hasCameraPermission() {
        return checkSelfPermission(Manifest.permission.CAMERA)
                == PackageManager.PERMISSION_GRANTED;
    }

    // Preview surface

    @Override
    public void onSurfaceTextureAvailable(final SurfaceTexture surface, final int width,
            final int height) {
        if (mCameraHandler != null) {
            openCamera();
        }
    }

    @Override
    public void onSurfaceTextureSizeChanged(final SurfaceTexture surface, final int width,
            final int height) {
        updateTransform();
    }

    @Override
    public boolean onSurfaceTextureDestroyed(final SurfaceTexture surface) {
        return true;
    }

    @Override
    public void onSurfaceTextureUpdated(final SurfaceTexture surface) {
        // Nothing: frames are decoded from the image reader.
    }

    // Camera

    private void openCamera() {
        if (mCamera != null || mFrames != null) {
            return; // Already open, or opening.
        }
        final CameraManager manager = getSystemService(CameraManager.class);
        boolean locked = false;
        try {
            final String cameraId = manager == null ? null : findBackCamera(manager);
            if (cameraId == null) {
                mStatus.setText(R.string.cifra_qr_camera_error);
                return;
            }
            final CameraCharacteristics characteristics =
                    manager.getCameraCharacteristics(cameraId);
            final StreamConfigurationMap map = characteristics.get(
                    CameraCharacteristics.SCALER_STREAM_CONFIGURATION_MAP);
            final Integer orientation = characteristics.get(
                    CameraCharacteristics.SENSOR_ORIENTATION);
            mSensorOrientation = orientation == null ? 90 : orientation;
            mAfMode = chooseAfMode(characteristics.get(
                    CameraCharacteristics.CONTROL_AF_AVAILABLE_MODES));
            final Size size = chooseFrameSize(map == null ? null
                    : map.getOutputSizes(ImageFormat.YUV_420_888));
            if (size == null) {
                mStatus.setText(R.string.cifra_qr_camera_error);
                return;
            }
            mFrameSize = size;
            final ImageReader frames = ImageReader.newInstance(size.getWidth(),
                    size.getHeight(), ImageFormat.YUV_420_888, 2);
            frames.setOnImageAvailableListener(this::onFrame, mCameraHandler);
            mFrames = frames;
            updateTransform();
            locked = mOpenCloseLock.tryAcquire(2500, TimeUnit.MILLISECONDS);
            if (!locked) {
                mStatus.setText(R.string.cifra_qr_camera_error);
                return;
            }
            manager.openCamera(cameraId, new CameraDevice.StateCallback() {
                @Override
                public void onOpened(final CameraDevice camera) {
                    mCamera = camera;
                    mOpenCloseLock.release();
                    startPreview(camera);
                }

                @Override
                public void onDisconnected(final CameraDevice camera) {
                    mOpenCloseLock.release();
                    camera.close();
                    mCamera = null;
                }

                @Override
                public void onError(final CameraDevice camera, final int error) {
                    mOpenCloseLock.release();
                    camera.close();
                    mCamera = null;
                    showStatus(R.string.cifra_qr_camera_error);
                }
            }, mCameraHandler);
        } catch (CameraAccessException | SecurityException | IllegalArgumentException e) {
            Log.w(TAG, "Could not open the camera", e);
            if (locked) {
                // The open failed before any callback could release it.
                mOpenCloseLock.release();
            }
            mStatus.setText(R.string.cifra_qr_camera_error);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    @SuppressWarnings("deprecation")
    private void startPreview(final CameraDevice camera) {
        final SurfaceTexture texture = mPreview.getSurfaceTexture();
        final ImageReader frames = mFrames;
        final Size size = mFrameSize;
        if (texture == null || frames == null || size == null) {
            return;
        }
        texture.setDefaultBufferSize(size.getWidth(), size.getHeight());
        final Surface preview = new Surface(texture);
        try {
            final CaptureRequest.Builder request = camera.createCaptureRequest(
                    CameraDevice.TEMPLATE_PREVIEW);
            request.addTarget(preview);
            request.addTarget(frames.getSurface());
            request.set(CaptureRequest.CONTROL_MODE, CaptureRequest.CONTROL_MODE_AUTO);
            request.set(CaptureRequest.CONTROL_AF_MODE, mAfMode);
            camera.createCaptureSession(Arrays.asList(preview, frames.getSurface()),
                    new CameraCaptureSession.StateCallback() {
                        @Override
                        public void onConfigured(final CameraCaptureSession session) {
                            if (mCamera == null) {
                                return;
                            }
                            mSession = session;
                            try {
                                session.setRepeatingRequest(request.build(), null,
                                        mCameraHandler);
                            } catch (CameraAccessException | IllegalStateException e) {
                                Log.w(TAG, "Could not start the preview", e);
                                showStatus(R.string.cifra_qr_camera_error);
                            }
                        }

                        @Override
                        public void onConfigureFailed(final CameraCaptureSession session) {
                            showStatus(R.string.cifra_qr_camera_error);
                        }
                    }, mCameraHandler);
        } catch (CameraAccessException | IllegalStateException e) {
            Log.w(TAG, "Could not start the preview", e);
            showStatus(R.string.cifra_qr_camera_error);
        }
    }

    private void closeCamera() {
        boolean locked = false;
        try {
            // Waits for a camera being opened, but never hangs the screen on a stuck one.
            locked = mOpenCloseLock.tryAcquire(2500, TimeUnit.MILLISECONDS);
            if (mSession != null) {
                mSession.close();
                mSession = null;
            }
            if (mCamera != null) {
                mCamera.close();
                mCamera = null;
            }
            if (mFrames != null) {
                mFrames.close();
                mFrames = null;
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        } finally {
            if (locked) {
                mOpenCloseLock.release();
            }
        }
    }

    private static String findBackCamera(final CameraManager manager)
            throws CameraAccessException {
        final String[] ids = manager.getCameraIdList();
        for (final String id : ids) {
            final Integer facing = manager.getCameraCharacteristics(id).get(
                    CameraCharacteristics.LENS_FACING);
            if (facing != null && facing == CameraCharacteristics.LENS_FACING_BACK) {
                return id;
            }
        }
        return ids.length > 0 ? ids[0] : null;
    }

    private static int chooseAfMode(final int[] modes) {
        int chosen = CaptureRequest.CONTROL_AF_MODE_OFF;
        if (modes != null) {
            for (final int mode : modes) {
                if (mode == CaptureRequest.CONTROL_AF_MODE_CONTINUOUS_PICTURE) {
                    return mode;
                }
                if (mode == CaptureRequest.CONTROL_AF_MODE_AUTO) {
                    chosen = mode;
                }
            }
        }
        return chosen;
    }

    /** The largest frame up to {@link #MAX_FRAME_PIXELS}, or the smallest if all are larger. */
    private static Size chooseFrameSize(final Size[] sizes) {
        if (sizes == null || sizes.length == 0) {
            return null;
        }
        Size best = null;
        Size smallest = sizes[0];
        for (final Size size : sizes) {
            final long pixels = (long) size.getWidth() * size.getHeight();
            if (pixels < (long) smallest.getWidth() * smallest.getHeight()) {
                smallest = size;
            }
            if (pixels <= MAX_FRAME_PIXELS && (best == null
                    || pixels > (long) best.getWidth() * best.getHeight())) {
                best = size;
            }
        }
        return best != null ? best : smallest;
    }

    /**
     * The camera turns the preview upright for the phone's natural orientation, but the view
     * stretches it to its own shape: scale it back to the frame's proportions, cropping the
     * excess. The screen asks for portrait, but Android 16 ignores that on large screens, so a
     * turned screen is handled too.
     */
    @SuppressWarnings("deprecation")
    private void updateTransform() {
        runOnUiThread(() -> {
            final Size size = mFrameSize;
            final int viewWidth = mPreview.getWidth();
            final int viewHeight = mPreview.getHeight();
            if (size == null || viewWidth == 0 || viewHeight == 0) {
                return;
            }
            final int rotation = getWindowManager().getDefaultDisplay().getRotation();
            final float centerX = viewWidth / 2f;
            final float centerY = viewHeight / 2f;
            final Matrix matrix = new Matrix();
            if (rotation == Surface.ROTATION_90 || rotation == Surface.ROTATION_270) {
                final RectF view = new RectF(0, 0, viewWidth, viewHeight);
                final RectF frame = new RectF(0, 0, size.getHeight(), size.getWidth());
                frame.offset(centerX - frame.centerX(), centerY - frame.centerY());
                matrix.setRectToRect(view, frame, Matrix.ScaleToFit.FILL);
                final float scale = Math.max((float) viewHeight / size.getHeight(),
                        (float) viewWidth / size.getWidth());
                matrix.postScale(scale, scale, centerX, centerY);
                matrix.postRotate(90 * (rotation - 2), centerX, centerY);
            } else {
                final boolean sideways = mSensorOrientation % 180 != 0;
                final float frameWidth = sideways ? size.getHeight() : size.getWidth();
                final float frameHeight = sideways ? size.getWidth() : size.getHeight();
                final float scale = Math.max(viewWidth / frameWidth, viewHeight / frameHeight);
                matrix.setScale(scale * frameWidth / viewWidth, scale * frameHeight / viewHeight,
                        centerX, centerY);
                if (rotation == Surface.ROTATION_180) {
                    matrix.postRotate(180, centerX, centerY);
                }
            }
            mPreview.setTransform(matrix);
        });
    }

    // Decoding, on the camera thread

    private void onFrame(final ImageReader reader) {
        final Image image = reader.acquireLatestImage();
        if (image == null) {
            return;
        }
        final int width;
        final int height;
        final int rowStride;
        try {
            if (mFound) {
                return;
            }
            width = image.getWidth();
            height = image.getHeight();
            // Only the brightness (Y) plane matters for a black and white code.
            final Image.Plane plane = image.getPlanes()[0];
            rowStride = plane.getRowStride();
            final ByteBuffer buffer = plane.getBuffer();
            final int length = rowStride * height;
            if (mLuminance == null || mLuminance.length < length) {
                mLuminance = new byte[length];
            }
            buffer.get(mLuminance, 0, Math.min(buffer.remaining(), length));
        } finally {
            image.close();
        }
        // The middle square: where the user aims, and less work per frame.
        final int side = Math.min(width, height);
        final QrCodes.Content content = QrCodes.decode(new PlanarYUVLuminanceSource(mLuminance,
                rowStride, height, (width - side) / 2, (height - side) / 2, side, side, false),
                false);
        if (content == null) {
            return;
        }
        if (mKind == KIND_MESSAGE && QrCodes.isPart(content)) {
            final byte[] wire = mAssembler.add(content);
            if (wire == null) {
                showProgress();
                return;
            }
            mFound = true;
            final QrCodes.Content message = new QrCodes.Content(wire, null);
            runOnUiThread(() -> finishWith(message));
            return;
        }
        final boolean wanted = mKind == KIND_KEY ? QrCodes.publicKey(content) != null
                : QrCodes.messageWire(content) != null;
        if (!wanted) {
            showStatus(mKind == KIND_KEY ? R.string.cifra_qr_not_key
                    : R.string.cifra_qr_not_message);
            return;
        }
        mFound = true;
        runOnUiThread(() -> finishWith(content));
    }

    private void showProgress() {
        final int received = mAssembler.received();
        if (received == mShownParts) {
            return;
        }
        mShownParts = received;
        final String progress = getString(R.string.cifra_qr_parts, received, mAssembler.total());
        runOnUiThread(() -> mStatus.setText(progress));
    }

    private void showStatus(final int message) {
        runOnUiThread(() -> mStatus.setText(message));
    }

    private void finishWith(final QrCodes.Content content) {
        if (mDelivered) {
            return;
        }
        mDelivered = true;
        deliver(mRequestId, content);
        finish();
    }
}
